"""
The vendored knowledge base: the IANA cipher-suite registry and the rule base.

Two deliberate choices here, both learned the hard way.

**This file exists.** Without it the directory is a *namespace* package, whose
module spec has ``origin is None``. On Python 3.9 —  the version Apple ships
with the macOS Command Line Tools, so a very common one to be handed —
``importlib.resources.files()`` resolves a package by doing:

    package_directory = pathlib.Path(spec.origin).parent

which on a namespace package is ``pathlib.Path(None)``:

    TypeError: expected str, bytes or os.PathLike object, not NoneType

Python 3.10 and newer handle namespace packages there, so the failure appears
only on 3.9 — and the whole engine dies on the first capture with a traceback
that says nothing about the actual cause. It also made a container and a laptop
behave differently while running byte-identical code, because the container's
Python happened to be newer.

**The files are located relative to ``__file__``, not through
``importlib.resources``.** Adding this file is enough to fix 3.9, but the
version-sensitive API buys us nothing: ``importlib.resources`` exists to read
data out of zipped imports, and this engine is always installed as real files —
editable from a checkout, or unpacked from a wheel. Locating them the plain way
removes an entire class of version-dependent behaviour, and it matches how the
other two data directories (``report/templates`` and ``ml/artifacts``) have
always been found.
"""

from __future__ import annotations

import os

KB_DIR = os.path.dirname(os.path.abspath(__file__))

RULES_FILE = "rules.yaml"
CIPHER_SUITES_FILE = "cipher_suites.json"
STANDARDS_FILE = "standards.yaml"



def kb_path(name: str) -> str:
    """Absolute path to a knowledge-base file shipped alongside this module."""
    path = os.path.join(KB_DIR, name)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"knowledge base file '{name}' is missing from {KB_DIR}. The engine "
            f"cannot run without it — reinstall with ./scripts/setup.sh."
        )
    return path


def load_standards() -> dict[str, dict[str, Any]]:
    """
    Load the standards knowledge base (standards.yaml).

    Returns a dict mapping finding/control IDs to their standards metadata:
    {
        "SMS-AUTH-001": {
            "standards": ["RFC 3207", "RFC 8314"],
            "applicability": "...",
        },
        ...
    }
    """
    import yaml
    from functools import lru_cache

    @lru_cache(maxsize=1)
    def _load() -> dict[str, dict[str, Any]]:
        path = kb_path(STANDARDS_FILE)
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        return doc.get("standards", {})

    return _load()
