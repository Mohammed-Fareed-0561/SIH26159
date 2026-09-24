"""
PCAP and PCAPNG file readers — security-hardened.

Both classic libpcap and the pcapng block format are implemented directly so
the engine has no native dependency and full control over timestamp
resolution — which matters more than it sounds.

Security changes (Phase 1):
- gzip decompression is bounded: a configurable max decompressed size prevents
  a compressed file from expanding until it exhausts memory.
- file size and packet count are checked before and during parsing so a
  malformed or malicious capture cannot consume unbounded resources.
- a structured AnalysisError (analysis_result.py) is raised on rejection so
  the subprocess layer returns a clean machine-readable error to the API.
"""
from __future__ import annotations

import gzip
import io
import statistics
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import BinaryIO, Iterator, Optional

from ..analysis_result import (
    AnalysisError,
    AnalysisLimits,
    AnalysisStatus,
    RejectionReason,
)
from .. import config as _cfg
from .layers import (
    ETH_P_IP,
    TcpSegment,
    UdpDatagram,
    parse_ip_tcp,
    parse_ip_udp,
    strip_link_layer,
)

# classic pcap magics
PCAP_MAGIC_BE = 0xA1B2C3D4        # seconds + microseconds, big endian
PCAP_MAGIC_LE = 0xD4C3B2A1
PCAP_MAGIC_NS_BE = 0xA1B23C4D     # seconds + nanoseconds
PCAP_MAGIC_NS_LE = 0x4D3CB2A1

# pcapng block types
BT_SHB = 0x0A0D0D0A
BT_IDB = 0x00000001
BT_PB = 0x00000002                # obsolete Packet Block
BT_SPB = 0x00000003               # Simple Packet Block
BT_EPB = 0x00000006               # Enhanced Packet Block

BYTE_ORDER_MAGIC = 0x1A2B3C4D

# A timestamp further than this from the capture median is treated as corrupt.
TIMESTAMP_OUTLIER_SECONDS = 86400 * 365  # one year


class CaptureFormatError(ValueError):
    """Raised when a file is not a recognisable packet capture."""


class CaptureSecurityError(ValueError):
    """Raised when a capture violates configured size / decompression limits."""


@dataclass
class RawPacket:
    number: int                 # 1-based frame number, as Wireshark shows it
    timestamp: float            # epoch seconds, float
    data: bytes
    dlt: int
    captured_len: int
    original_len: int

    @property
    def truncated(self) -> bool:
        return self.captured_len < self.original_len


@dataclass
class CaptureMeta:
    format: str = "pcap"
    link_types: list[int] = field(default_factory=list)
    packet_count: int = 0
    truncated_packets: int = 0
    first_time: Optional[float] = None
    last_time: Optional[float] = None
    median_time: Optional[float] = None
    suspect_timestamps: int = 0


def _limits() -> AnalysisLimits:
    return AnalysisLimits(
        max_input_bytes=_cfg.MAX_CAPTURE_BYTES,
        max_decompressed_bytes=_cfg.MAX_DECOMPRESSED_BYTES,
        max_packet_count=_cfg.MAX_PACKET_COUNT,
    )


def _check_file_size(path: str) -> int:
    """Return the raw file size, raising CaptureSecurityError if it exceeds the limit."""
    size = 0
    try:
        size = io.open(path, "rb").seek(0, 2)
    except OSError:
        return 0
    if size > _cfg.MAX_CAPTURE_BYTES:
        raise CaptureSecurityError(
            AnalysisError(
                status=AnalysisStatus.REJECTED,
                reason=RejectionReason.SIZE_LIMIT_EXCEEDED,
                message=f"capture file is {size / (1024*1024):.1f} MB, "
                        f"exceeds the {_cfg.MAX_CAPTURE_BYTES // (1024*1024)} MB limit",
                limits=_limits(),
            )
        )
    return size


class _BoundedGzipReader:
    """
    A gzip decompressor that refuses to expand beyond MAX_DECOMPRESSED_BYTES.
    """

    def __init__(self, path: str, max_bytes: Optional[int] = None):
        self._raw = open(path, "rb")
        self._decoder = gzip.GzipFile(fileobj=self._raw)
        self._max = max_bytes if max_bytes is not None else _cfg.MAX_DECOMPRESSED_BYTES
        self._total = 0
        self._buf = bytearray()

    def read(self) -> bytes:
        """Read the entire (bounded) decompressed content."""
        while True:
            chunk = self._decoder.read(64 * 1024)
            if not chunk:
                break
            self._total += len(chunk)
            if self._total > self._max:
                raise CaptureSecurityError(
                    AnalysisError(
                        status=AnalysisStatus.REJECTED,
                        reason=RejectionReason.DECOMPRESSED_SIZE_LIMIT_EXCEEDED,
                        message=f"decompressed size exceeds the "
                                f"{self._max // (1024*1024)} MB limit",
                        limits=_limits(),
                    )
                )
            self._buf.extend(chunk)
        return bytes(self._buf)

    def close(self) -> None:
        try:
            self._raw.close()
        except OSError:
            pass

    def __enter__(self) -> "_BoundedGzipReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _open_maybe_gzip(path: str) -> tuple[BinaryIO, str]:
    """
    Transparently handle .gz captures with bounded decompression.

    Returns (stream, format_suffix).  The stream is always seekable enough
    for the pcap parsers that follow.
    """
    with open(path, "rb") as probe:
        head = probe.read(2)
    if head == b"\x1f\x8b":
        bounded = _BoundedGzipReader(path)
        try:
            raw = bounded.read()
            bounded.close()
        except CaptureSecurityError:
            bounded.close()
            raise
        return io.BytesIO(raw), ".gz"
    return open(path, "rb"), ""


# -----------------------------------------------------------------------------
# classic pcap
# -----------------------------------------------------------------------------

class PcapReader:
    def __init__(self, stream: BinaryIO):
        self.stream = stream
        header = stream.read(24)
        if len(header) < 24:
            raise CaptureFormatError("file too short for a pcap global header")
        raw = struct.unpack("<I", header[:4])[0]
        if raw == PCAP_MAGIC_BE:
            self.endian, self.ts_divisor = "<", 1e6
        elif raw == PCAP_MAGIC_NS_BE:
            self.endian, self.ts_divisor = "<", 1e9
        elif raw == PCAP_MAGIC_LE:
            self.endian, self.ts_divisor = ">", 1e6
        elif raw == PCAP_MAGIC_NS_LE:
            self.endian, self.ts_divisor = ">", 1e9
        else:
            raise CaptureFormatError(f"unrecognised pcap magic 0x{raw:08x}")
        fields = struct.unpack(self.endian + "HHiIII", header[4:24])
        self.version = (fields[0], fields[1])
        self.snaplen = fields[4]
        self.dlt = fields[5]

    def packets(self) -> Iterator[RawPacket]:
        n = 0
        while True:
            hdr = self.stream.read(16)
            if len(hdr) < 16:
                return
            ts_sec, ts_frac, incl, orig = struct.unpack(self.endian + "IIII", hdr)
            if incl > 0x7FFFFFFF:
                return
            data = self.stream.read(incl)
            if len(data) < incl:
                return
            n += 1
            if n > _cfg.MAX_PACKET_COUNT:
                raise CaptureSecurityError(
                    AnalysisError(
                        status=AnalysisStatus.REJECTED,
                        reason=RejectionReason.PACKET_COUNT_EXCEEDED,
                        message=f"packet count exceeds the {_cfg.MAX_PACKET_COUNT} limit",
                        limits=_limits(),
                    )
                )
            yield RawPacket(
                number=n,
                timestamp=ts_sec + ts_frac / self.ts_divisor,
                data=data,
                dlt=self.dlt,
                captured_len=incl,
                original_len=orig,
            )


# -----------------------------------------------------------------------------
# pcapng
# -----------------------------------------------------------------------------

class PcapNgReader:
    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.endian = "<"
        self.interfaces: list[tuple[int, float]] = []
        self._peek_shb()

    def _peek_shb(self) -> None:
        head = self.stream.read(12)
        if len(head) < 12:
            raise CaptureFormatError("file too short for a pcapng section header")
        btype = struct.unpack("<I", head[:4])[0]
        if btype != BT_SHB:
            raise CaptureFormatError("not a pcapng file")
        bom = struct.unpack("<I", head[8:12])[0]
        self.endian = "<" if bom == BYTE_ORDER_MAGIC else ">"
        self.stream.seek(0)

    @staticmethod
    def _tsresol_from_options(body: bytes, endian: str, opt_offset: int) -> float:
        off = opt_offset
        while off + 4 <= len(body):
            code, length = struct.unpack(endian + "HH", body[off:off + 4])
            off += 4
            if code == 0:
                break
            val = body[off:off + length]
            off += length
            off += (-length) % 4
            if code == 9 and len(val) >= 1:
                v = val[0]
                if v & 0x80:
                    return float(2 ** (v & 0x7F))
                return float(10 ** v)
        return 1e6

    def packets(self) -> Iterator[RawPacket]:
        n = 0
        e = self.endian
        while True:
            head = self.stream.read(8)
            if len(head) < 8:
                return
            btype, blen = struct.unpack(e + "II", head)
            if blen < 12:
                return
            body = self.stream.read(blen - 12)
            if len(body) < blen - 12:
                return
            self.stream.read(4)  # trailing block_total_length

            if btype == BT_SHB:
                self.interfaces = []
            elif btype == BT_IDB:
                if len(body) >= 8:
                    dlt = struct.unpack(e + "H", body[0:2])[0]
                    divisor = self._tsresol_from_options(body, e, 8)
                    self.interfaces.append((dlt, divisor))
            elif btype == BT_EPB:
                if len(body) < 20:
                    continue
                iface, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(e + "IIIII", body[:20])
                dlt, divisor = self.interfaces[iface] if iface < len(self.interfaces) else (1, 1e6)
                ts = ((ts_hi << 32) | ts_lo) / divisor
                data = body[20:20 + cap_len]
                n += 1
                if n > _cfg.MAX_PACKET_COUNT:
                    raise CaptureSecurityError(
                        AnalysisError(
                            status=AnalysisStatus.REJECTED,
                            reason=RejectionReason.PACKET_COUNT_EXCEEDED,
                            message=f"packet count exceeds the {_cfg.MAX_PACKET_COUNT} limit",
                            limits=_limits(),
                        )
                    )
                yield RawPacket(n, ts, data, dlt, cap_len, orig_len)
            elif btype == BT_SPB:
                if len(body) < 4:
                    continue
                orig_len = struct.unpack(e + "I", body[:4])[0]
                dlt, _ = self.interfaces[0] if self.interfaces else (1, 1e6)
                data = body[4:]
                n += 1
                if n > _cfg.MAX_PACKET_COUNT:
                    raise CaptureSecurityError(
                        AnalysisError(
                            status=AnalysisStatus.REJECTED,
                            reason=RejectionReason.PACKET_COUNT_EXCEEDED,
                            message=f"packet count exceeds the {_cfg.MAX_PACKET_COUNT} limit",
                            limits=_limits(),
                        )
                    )
                yield RawPacket(n, 0.0, data, dlt, len(data), orig_len)
            elif btype == BT_PB:
                if len(body) < 20:
                    continue
                iface, drops, ts_hi, ts_lo = struct.unpack(e + "HHII", body[:12])
                cap_len, orig_len = struct.unpack(e + "II", body[12:20])
                dlt, divisor = self.interfaces[iface] if iface < len(self.interfaces) else (1, 1e6)
                ts = ((ts_hi << 32) | ts_lo) / divisor
                data = body[20:20 + cap_len]
                n += 1
                if n > _cfg.MAX_PACKET_COUNT:
                    raise CaptureSecurityError(
                        AnalysisError(
                            status=AnalysisStatus.REJECTED,
                            reason=RejectionReason.PACKET_COUNT_EXCEEDED,
                            message=f"packet count exceeds the {_cfg.MAX_PACKET_COUNT} limit",
                            limits=_limits(),
                        )
                    )
                yield RawPacket(n, ts, data, dlt, cap_len, orig_len)


# -----------------------------------------------------------------------------
# unified entry point
# -----------------------------------------------------------------------------

class CaptureReader:
    """
    Opens a capture in any supported container and yields decoded TCP segments
    and UDP datagrams, while collecting capture-level metadata.
    """

    def __init__(self, path: str):
        self.path = path
        self.meta = CaptureMeta()
        self._packets: list[RawPacket] = []
        _check_file_size(path)
        try:
            self._load()
        except CaptureSecurityError:
            raise
        except CaptureFormatError:
            raise
        except MemoryError:
            raise CaptureSecurityError(
                AnalysisError(
                    status=AnalysisStatus.REJECTED,
                    reason=RejectionReason.SIZE_LIMIT_EXCEEDED,
                    message="capture exceeded available memory during parsing",
                    limits=_limits(),
                )
            )

    def _load(self) -> None:
        stream, gz = _open_maybe_gzip(self.path)
        try:
            head = stream.read(4)
            stream.seek(0)
            if len(head) < 4:
                raise CaptureFormatError("file is empty or truncated")
            if struct.unpack("<I", head)[0] == BT_SHB:
                reader: PcapReader | PcapNgReader = PcapNgReader(stream)
                self.meta.format = "pcapng" + gz
            else:
                reader = PcapReader(stream)
                self.meta.format = "pcap" + gz
            self._packets = list(reader.packets())
        except (struct.error, EOFError) as exc:
            raise CaptureFormatError(f"malformed capture data: {exc}")
        finally:
            try:
                stream.close()
            except Exception:
                pass

        self.meta.packet_count = len(self._packets)
        self.meta.link_types = sorted({p.dlt for p in self._packets})
        self.meta.truncated_packets = sum(1 for p in self._packets if p.truncated)

        times = [p.timestamp for p in self._packets if p.timestamp > 0]
        if times:
            median = statistics.median(times)
            self.meta.median_time = median
            sane = [t for t in times if abs(t - median) <= TIMESTAMP_OUTLIER_SECONDS]
            self.meta.suspect_timestamps = len(times) - len(sane)
            pool = sane or times
            self.meta.first_time = min(pool)
            self.meta.last_time = max(pool)

    # -- accessors ---------------------------------------------------------

    def raw_packets(self) -> list[RawPacket]:
        return self._packets

    def is_suspect_time(self, ts: float) -> bool:
        if self.meta.median_time is None or ts <= 0:
            return True
        return abs(ts - self.meta.median_time) > TIMESTAMP_OUTLIER_SECONDS

    def sane_time(self, ts: float) -> float:
        if self.is_suspect_time(ts):
            return self.meta.median_time or ts
        return ts

    def tcp_segments(self) -> Iterator[tuple[RawPacket, TcpSegment]]:
        for pkt in self._packets:
            net, etype = strip_link_layer(pkt.data, pkt.dlt)
            if net is None or etype is None:
                continue
            seg = parse_ip_tcp(net, etype)
            if seg is not None:
                yield pkt, seg

    def udp_datagrams(self) -> Iterator[tuple[RawPacket, UdpDatagram]]:
        for pkt in self._packets:
            net, etype = strip_link_layer(pkt.data, pkt.dlt)
            if net is None or etype is None:
                continue
            dg = parse_ip_udp(net, etype)
            if dg is not None:
                yield pkt, dg


def epoch_to_datetime(ts: Optional[float]) -> Optional[datetime]:
    if ts is None or ts <= 0:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
