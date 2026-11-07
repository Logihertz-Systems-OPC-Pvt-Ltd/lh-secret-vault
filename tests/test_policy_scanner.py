# ==============================================================================
# Product:       lh-secret-vault (lh-vault)
# Module:        tests.test_policy_scanner
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for vault manifest and policy scanner evaluating all 10 rules."""

from __future__ import annotations

from pathlib import Path

from lh_secret_vault.models import RULES_REGISTRY, FindingSeverity
from lh_secret_vault.policy_scanner import (
    find_vault_files,
    scan_env_file,
    scan_vault_file,
    scan_vault_target,
)

# --------------------------------------------------------------------------
# --- Rule LH-VAULT-001 (CRITICAL):
#     Unencrypted Plaintext Secret in Vault Manifest
# ---
# Evaluates security posture against unencrypted plaintext secret in vault
# manifest.
# Rationale: Prevents policy violations and reduces vulnerable surface exposure.
# False Positive Defense: Contextual inspection ensures intentional configs are
# respected.
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# --- Rule LH-VAULT-010: Missing Secret Governance Metadata (LOW) ---
# Evaluates security posture against missing secret governance metadata.
# Rationale: Prevents policy violations and reduces vulnerable surface exposure.
# False Positive Defense: Contextual inspection ensures intentional configs are
# respected.
# --------------------------------------------------------------------------


def test_rules_registry_contains_ten_rules() -> None:
    """Verify rules LH-VAULT-001 through LH-VAULT-010 are registered."""
    for i in range(1, 11):
        rule_id = f"LH-VAULT-{i:03d}"
        assert rule_id in RULES_REGISTRY
        assert RULES_REGISTRY[rule_id].title
        assert RULES_REGISTRY[rule_id].remediation


def test_find_vault_files(tmp_path: Path) -> None:
    """Test discovering vault manifests and env files."""
    v1 = tmp_path / "app.vault.yaml"
    v1.write_text("cipher: AES-256-GCM\n", encoding="utf-8")
    env = tmp_path / ".env"
    env.write_text("KEY=val\n", encoding="utf-8")
    other = tmp_path / "readme.txt"
    other.write_text("hello\n", encoding="utf-8")

    files = find_vault_files(tmp_path)
    file_names = {f.name for f in files}
    assert "app.vault.yaml" in file_names
    assert ".env" in file_names
    assert "readme.txt" not in file_names


def test_scan_env_file(insecure_env_file: Path) -> None:
    """Test detecting unencrypted credentials in .env file (LH-VAULT-001)."""
    findings = scan_env_file(insecure_env_file)
    assert len(findings) >= 2
    for f in findings:
        assert f.rule_id == "LH-VAULT-001"
        assert f.severity == FindingSeverity.CRITICAL


def test_scan_vulnerable_vault_manifest(vulnerable_vault_manifest: Path) -> None:
    """Validate detection of LH-VAULT-001 through LH-VAULT-010."""
    findings = scan_vault_file(vulnerable_vault_manifest)
    rule_ids = {f.rule_id for f in findings}

    assert "LH-VAULT-001" in rule_ids  # unencrypted_api_key
    assert "LH-VAULT-002" in rule_ids  # AES-ECB and DES / MD5
    assert "LH-VAULT-003" in rule_ids  # master_key
    assert "LH-VAULT-004" in rule_ids  # 0777 file_mode and permissions
    assert "LH-VAULT-005" in rule_ids  # expired_at and rotation
    assert "LH-VAULT-006" in rule_ids  # cli_args, core_dumps, temp files
    assert "LH-VAULT-007" in rule_ids  # truncated tag / iv
    assert "LH-VAULT-008" in rule_ids  # allowed_processes: ["*"]
    assert "LH-VAULT-009" in rule_ids  # audit_logging: false
    assert "LH-VAULT-010" in rule_ids  # missing governance metadata


def test_scan_clean_vault_project(clean_vault_project: Path) -> None:
    """Test clean zero-trust vault project produces zero findings."""
    report = scan_vault_target(clean_vault_project)
    assert report.findings_count == 0
    assert len(report.findings) == 0
