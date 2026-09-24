"""
The engine's process boundary — not a user interface.

The web UI is the only interface to SecureMailScope. This module exists so the
Spring Boot backend can run the analysis out-of-process, which is a deliberate
containment choice: a malformed capture that crashes a parser takes down a
subprocess, not the API.

Exactly three commands, and each maps to something the backend does:

    python -m securemailscope.cli analyse <pcap> --json -     upload  -> report
    python -m securemailscope.cli render - --html -           report  -> HTML
    python -m securemailscope.ml.train                        build the model

Security (Phase 1): structured errors are emitted for rejections instead of
raising exceptions that would produce a stack trace on stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from .analysis_result import AnalysisError
from .pipeline import analyse_capture
from .report import html_report, json_report


def _emit_error(err: AnalysisError) -> int:
    """Write a structured error document to stdout and return a non-zero exit code."""
    json.dump(err.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 2


def cmd_analyse(args: argparse.Namespace) -> int:
    if sys.platform.startswith('linux'):
        import resource
        limit = int(os.environ.get('SMS_MAX_MEMORY_MB', '4096')) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    if not os.path.exists(args.pcap):
        err = AnalysisError(
            status="failed",
            reason="invalid_capture",
            message=f"no such file: {args.pcap}",
            limits={"max_input_bytes": 0, "max_decompressed_bytes": 0, "max_packet_count": 0},
        )
        return _emit_error(err)

    history = json.loads(_read_text(args.history)) if args.history else []
    def progress(stage):
        print("SMS_PROGRESS:" + stage, file=sys.stderr, flush=True)
    try:
        report = analyse_capture(args.pcap, run_ml=not args.no_ml, model_path=args.model, progress=progress, history=history)
    except AnalysisError as exc:
        return _emit_error(exc)
    except Exception as exc:
        err = AnalysisError(
            status="failed",
            reason="internal_error",
            message=str(exc)[:500],
            limits={"max_input_bytes": 0, "max_decompressed_bytes": 0, "max_packet_count": 0},
        )
        return _emit_error(err)
    payload = json_report.dumps(report, indent=None if args.compact else 2)

    if args.json == "-":
        sys.stdout.write(payload)
        sys.stdout.write("\n")
    else:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(payload)
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    raw = sys.stdin.read() if args.report == "-" else _read_text(args.report)
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"not a JSON report: {exc}", file=sys.stderr)
        return 2
    if not isinstance(document, dict) or "sessions" not in document:
        if isinstance(document, dict) and "status" in document:
            # Pass through structured errors from the analyse step.
            json.dump(document, sys.stdout, indent=2)
            sys.stdout.write("\n")
            return 2
        print("not a SecureMailScope report: no 'sessions' key", file=sys.stderr)
        return 2

    html = html_report.render_document(document)
    if args.html == "-":
        sys.stdout.write(html)
    else:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"wrote {args.html}", file=sys.stderr)
    return 0


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def cmd_train(args: argparse.Namespace) -> int:
    from .ml.train import train_and_save

    rep = train_and_save(
        n_profiles=args.profiles,
        sessions_per_profile=args.sessions_per_profile,
        tls13_mask_rate=args.tls13_mask_rate,
        seed=args.seed,
    )
    print(f"trained on {rep.n_samples} samples from {rep.n_groups} configurations")
    print(f"macro-F1 {rep.macro_f1_mean:.4f} +/- {rep.macro_f1_std:.4f}  "
          f"accuracy {rep.accuracy_mean:.4f}")
    v = rep.by_certificate_visibility
    if v:
        print(f"cert visible acc={v.get('cert_visible_accuracy')} "
              f"(baseline {v.get('cert_visible_baseline')})")
        print(f"cert masked  acc={v.get('cert_masked_accuracy')} "
              f"(baseline {v.get('cert_masked_baseline')})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="securemailscope",
        description="Passive cryptographic posture assessment for SMTP/IMAP/POP3 from PCAP.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyse", aliases=["analyze"], help="analyse a capture, emit JSON")
    a.add_argument("pcap", help="path to a .pcap, .pcapng or .pcap.gz file")
    a.add_argument("--json", metavar="PATH", default="-",
                   help="where to write the report; '-' (the default) is stdout")
    a.add_argument("--compact", action="store_true", help="minified JSON")
    a.add_argument("--no-ml", action="store_true", help="skip the model stage")
    a.add_argument("--model", metavar="PATH", help="path to a model bundle")
    a.add_argument("--history", help="JSON array of earlier investigation reports")
    a.set_defaults(func=cmd_analyse)

    d = sub.add_parser(
        "render",
        help="render a stored JSON report to HTML (no capture file needed)",
    )
    d.add_argument("report", help="path to a JSON report written by `analyse --json` ('-' for stdin)")
    d.add_argument("--html", metavar="PATH", default="-",
                   help="where to write the HTML; '-' (the default) is stdout")
    d.set_defaults(func=cmd_render)

    t = sub.add_parser("train", help="train the posture model")
    t.add_argument("--profiles", type=int, default=260)
    t.add_argument("--sessions-per-profile", type=int, default=8)
    t.add_argument("--tls13-mask-rate", type=float, default=0.30)
    t.add_argument("--seed", type=int, default=26159)
    t.set_defaults(func=cmd_train)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
