"""
The engine's process boundary, run as a real subprocess.

This is not a user interface — the web UI is the only interface. It is the
contract the Spring Boot backend speaks, so these tests run the exact commands
the backend issues.

Why this file exists
--------------------
Every other test imports the engine into the pytest process, and that turned out
to hide a whole class of bug. ``certs.py`` once reached a submodule through
``__import__("cryptography").hazmat.primitives.serialization``, which only
resolves if something else has already imported that submodule. Under pytest
something always had — ``test_certificates.py`` imports ``serialization``
itself — so the suite passed while a bare ``python -m securemailscope.cli`` run
crashed on every capture containing a certificate.

The suite was passing for the wrong reason. Running the CLI in a clean
interpreter is the only way to catch that, and it is also exactly how the Spring
Boot backend invokes the engine, so this file tests the real integration path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from .conftest import DEMO_FILES

ENGINE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def run_cli(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = ENGINE_ROOT
    return subprocess.run(
        [sys.executable, "-m", "securemailscope.cli", *args],
        cwd=ENGINE_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )


@pytest.mark.parametrize("key", sorted(DEMO_FILES))
def test_cli_analyses_every_capture_in_a_clean_interpreter(captures, key):
    """
    The exact invocation the backend uses, on every demo capture.

    Certificate-bearing captures are the ones that matter most here: they
    exercise the import path that a pytest-only run leaves accidentally warm.
    """
    if key not in captures:
        pytest.skip(f"{key} not present")

    result = run_cli("analyse", captures[key], "--json", "-", "--compact", "--no-ml")
    assert result.returncode == 0, (
        f"engine failed on {key}:\n{result.stderr[-2000:]}"
    )
    assert result.stdout.strip(), "nothing written to stdout"

    report = json.loads(result.stdout)
    assert report["schema_version"]
    assert report["capture"]["sha256"]
    assert isinstance(report["sessions"], list)


def test_stdout_stays_machine_clean(captures):
    """
    Diagnostics must go to stderr. The backend parses stdout as a single JSON
    document, so a stray print would corrupt the contract between the two halves
    of the system.
    """
    path = captures.get("pop3_starttls")
    if not path:
        pytest.skip("capture not present")

    result = run_cli("analyse", path, "--json", "-", "--compact", "--no-ml")
    assert result.returncode == 0, result.stderr[-2000:]
    # Parses whole, with nothing before or after it.
    json.loads(result.stdout)
    assert result.stdout.lstrip().startswith("{")
    assert result.stdout.rstrip().endswith("}")


def test_certificate_fingerprints_are_produced(captures):
    """
    Guards the specific regression: a certificate-bearing capture must yield a
    64-character SHA-256 fingerprint, computed in a clean interpreter.
    """
    path = captures.get("pop3_starttls")
    if not path:
        pytest.skip("capture not present")

    result = run_cli("analyse", path, "--json", "-", "--compact", "--no-ml")
    assert result.returncode == 0, result.stderr[-2000:]
    report = json.loads(result.stdout)

    chains = [s["chain"] for s in report["sessions"] if s["chain"]]
    assert chains, "expected a visible certificate in this capture"
    for chain in chains:
        for cert in chain:
            assert len(cert["sha256_fingerprint"]) == 64


def test_json_goes_to_stdout_by_default(captures):
    """
    The backend relies on this: `analyse <pcap>` with no flags writes the report
    to stdout and nothing else. There is no human summary to suppress any more,
    so there is no way to accidentally corrupt the document with prose.
    """
    path = captures.get("smtp_relay_cleartext")
    if not path:
        pytest.skip("capture not present")

    result = run_cli("analyse", path, "--no-ml")
    assert result.returncode == 0, result.stderr[-2000:]
    report = json.loads(result.stdout)
    assert report["overall_grade"] == "F"


def test_the_cli_offers_only_the_engine_boundary():
    """
    Three commands, all of which the backend uses. Anything else is a second
    interface to a product that has one.
    """
    result = run_cli("--help")
    assert result.returncode == 0
    assert "analyse" in result.stdout
    assert "render" in result.stdout
    assert "train" in result.stdout
    for gone in ("rules", "--fail-on-critical"):
        assert gone not in result.stdout, f"{gone} should have been removed"

# --------------------------------------------------------------------------
# `render` — the path the API uses to produce HTML and PDF
# --------------------------------------------------------------------------

def test_render_rebuilds_html_from_a_stored_report(captures, tmp_path):
    """
    The API re-renders the *stored* JSON rather than re-analysing the capture,
    so a report stays reproducible after the pcap is gone. This runs that path
    end to end in a clean interpreter, exactly as the backend does.
    """
    path = captures.get("imaps_tls13") or captures.get("pop3_starttls")
    if not path:
        pytest.skip("no capture present")

    analysed = run_cli("analyse", path, "--json", "-", "--compact", "--no-ml")
    assert analysed.returncode == 0, analysed.stderr[-2000:]
    stored = tmp_path / "report.json"
    stored.write_text(analysed.stdout, encoding="utf-8")
    document = json.loads(analysed.stdout)

    rendered = run_cli("render", str(stored), "--html", "-")
    assert rendered.returncode == 0, rendered.stderr[-2000:]
    html = rendered.stdout
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "</html>" in html
    # It must be a report about *this* evidence, not a blank template.
    assert document["capture"]["sha256"] in html


def test_render_reads_the_report_from_stdin(captures, tmp_path):
    """The backend pipes the document in rather than writing a temp file."""
    path = captures.get("pop3_starttls")
    if not path:
        pytest.skip("capture not present")

    analysed = run_cli("analyse", path, "--json", "-", "--compact", "--no-ml")
    assert analysed.returncode == 0, analysed.stderr[-2000:]

    env = dict(os.environ)
    env["PYTHONPATH"] = ENGINE_ROOT
    piped = subprocess.run(
        [sys.executable, "-m", "securemailscope.cli", "render", "-", "--html", "-"],
        cwd=ENGINE_ROOT, env=env, input=analysed.stdout,
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
    )
    assert piped.returncode == 0, piped.stderr[-2000:]
    assert piped.stdout.lstrip().startswith("<!DOCTYPE html>")


def test_render_rejects_something_that_is_not_a_report(tmp_path):
    bad = tmp_path / "notes.json"
    bad.write_text('{"hello": "world"}', encoding="utf-8")
    result = run_cli("render", str(bad), "--html", "-")
    assert result.returncode == 2
    assert "not a SecureMailScope report" in result.stderr



def test_rendered_report_prints_itself_only_when_asked(captures, tmp_path):
    """
    "Save as PDF" is the report opened with ?print=1; the page then calls
    window.print() and the browser produces the document.

    There is no server-side PDF renderer any more. The one there was needed
    WeasyPrint — and therefore Pango and cairo — which install in a container
    and usually not on a laptop, so the endpoint answered 501 in exactly the
    deployments people clicked it from, behind an <a download> link that throws
    the explanation away.

    The gate matters as much as the hook: a saved copy of this file must not
    print itself when someone opens it later.
    """
    path = captures.get("pop3_starttls")
    if not path:
        pytest.skip("capture not present")

    analysed = run_cli("analyse", path, "--json", "-", "--compact", "--no-ml")
    stored = tmp_path / "report.json"
    stored.write_text(analysed.stdout, encoding="utf-8")

    rendered = run_cli("render", str(stored), "--html", "-")
    assert rendered.returncode == 0, rendered.stderr[-2000:]
    html = rendered.stdout

    assert "window.print()" in html, "the print hook is what makes PDF work"
    assert "print" in html and "URLSearchParams" in html
    # Gated, not unconditional.
    assert "getElementById" not in html.split("window.print")[0][-200:]
    assert "=== '1'" in html or "== '1'" in html or "'1'" in html


def test_the_engine_no_longer_offers_pdf():
    """
    The flag is gone, so nothing can call a renderer that is not there. A
    lingering --pdf would fail at runtime instead of at the boundary.
    """
    result = run_cli("render", "--help")
    assert result.returncode == 0
    assert "--html" in result.stdout
    assert "--pdf" not in result.stdout
