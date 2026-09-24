"""
SecureMailScope engine configuration.

Centralizes limits and constants so security boundaries are defined in one place.
"""
from __future__ import annotations

import os

# --- capture size limits ---------------------------------------------------------
# Can be overridden via environment variables.  All values are in megabytes.
MAX_CAPTURE_SIZE_MB = int(os.environ.get("SMS_MAX_CAPTURE_SIZE_MB", "2048"))
MAX_DECOMPRESSED_SIZE_MB = int(os.environ.get("SMS_MAX_DECOMPRESSED_SIZE_MB", "4096"))

# Derived byte limits.
MAX_CAPTURE_BYTES = MAX_CAPTURE_SIZE_MB * 1024 * 1024
MAX_DECOMPRESSED_BYTES = MAX_DECOMPRESSED_SIZE_MB * 1024 * 1024

# --- packet / processing limits -------------------------------------------------
MAX_PACKET_COUNT = int(os.environ.get("SMS_MAX_PACKET_COUNT", "5000000"))
