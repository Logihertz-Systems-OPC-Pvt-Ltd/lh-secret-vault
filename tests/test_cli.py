# ==============================================================================
# Product:       lh-secret-vault (lh-vault)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Integration tests for lh-secret-vault command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from lh_secret_vault.cli import app

runner = CliRunner()
ENV = {"COLUMNS": "160", "NO_COLOR": "1", "TERM": "dumb"}


def test_cli_rules_command() -> None:
    """Test listing all LH-VAULT detection rules."""
    result = runner.invoke(app, ["rules"], env=ENV)
    assert result.exit_code == 0
    assert "LH-VAULT-001" in result.output
    assert "LH-VAULT-010" in result.output
    assert "Unencrypted Plaintext Secret" in result.output


def test_cli_scan_clean_project(clean_vault_project: Path) -> None:
    """Test scan command on clean vault passes with exit code 0."""
    result = runner.invoke(app, ["scan", str(clean_vault_project)], env=ENV)
    assert result.exit_code == 0
    assert "Scan Clean" in result.output or "No secret vault vulnerabilities" in result.output


def test_cli_scan_vulnerable_fails_threshold(vulnerable_vault_manifest: Path) -> None:
    """Test scan command on vulnerable manifest triggers non-zero exit code."""
    result = runner.invoke(
        app,
        ["scan", str(vulnerable_vault_manifest), "--fail-on", "high"],
        env=ENV,
    )
    assert result.exit_code == 1
    assert "Scan failed" in result.output
    assert "LH-VAULT-001" in result.output


def test_cli_scan_fail_on_threshold_not_reached(tmp_path: Path) -> None:
    """Test scan passes when findings do not meet fail-on severity."""
    v_file = tmp_path / "low.vault.json"
    # Create file with only low finding (missing governance metadata)
    v_file.write_text(
        """{
  "vault_version": "1.0.0",
  "cipher": "AES-256-GCM",
  "audit": {"enabled": true},
  "secrets": {
    "api_token": {
      "cipher": "AES-256-GCM",
      "ciphertext": "YWJj",
      "iv": "MTIzNDU2Nzg5MDEy",
      "tag": "MTIzNDU2Nzg5MDEyMzQ1Ng=="
    }
  }
}
""",
        encoding="utf-8",
    )
    # Ensure compliant permissions
    try:
        os_chmod = __import__("os").chmod
        os_chmod(v_file, 0o600)
    except OSError:
        pass

    result = runner.invoke(
        app,
        ["scan", str(v_file), "--fail-on", "high"],
        env=ENV,
    )
    assert result.exit_code == 0


def test_cli_scan_format_json(vulnerable_vault_manifest: Path) -> None:
    """Test scan output with JSON format."""
    result = runner.invoke(
        app,
        ["scan", str(vulnerable_vault_manifest), "--format", "json", "--fail-on", "critical"],
        env=ENV,
    )
    assert "schema_version" in result.output
    data = json.loads(result.output.split("\nScan failed")[0].strip())
    assert data["scanner"] == "lh-secret-vault"
    assert data["findings_count"] > 0


def test_cli_scan_format_sarif(vulnerable_vault_manifest: Path) -> None:
    """Test scan output with SARIF format."""
    result = runner.invoke(
        app,
        ["scan", str(vulnerable_vault_manifest), "--format", "sarif", "--fail-on", "critical"],
        env=ENV,
    )
    assert "https://json.schemastore.org/sarif-2.1.0.json" in result.output
    data = json.loads(result.output.split("\nScan failed")[0].strip())
    assert data["version"] == "2.1.0"


def test_cli_scan_output_file(vulnerable_vault_manifest: Path, tmp_path: Path) -> None:
    """Test writing scan output to destination file."""
    out_file = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "scan",
            str(vulnerable_vault_manifest),
            "--format",
            "json",
            "--output",
            str(out_file),
            "--fail-on",
            "critical",
        ],
        env=ENV,
    )
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["scanner"] == "lh-secret-vault"
    assert "Report exported successfully" in result.output


def test_cli_scan_min_severity_filter(vulnerable_vault_manifest: Path) -> None:
    """Test filtering scan findings by minimum severity."""
    result = runner.invoke(
        app,
        [
            "scan",
            str(vulnerable_vault_manifest),
            "--min-severity",
            "critical",
            "--format",
            "json",
            "--fail-on",
            "critical",
        ],
        env=ENV,
    )
    data = json.loads(result.output.split("\nScan failed")[0].strip())
    for f in data["findings"]:
        assert f["severity"] == "CRITICAL"


def test_cli_scan_nonexistent_path() -> None:
    """Test scanning a nonexistent file path fails."""
    result = runner.invoke(app, ["scan", "/nonexistent/vault/path/9999"], env=ENV)
    assert result.exit_code != 0
