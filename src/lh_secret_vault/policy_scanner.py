# ==============================================================================
# Product:       lh-secret-vault (lh-vault)
# Module:        src.lh_secret_vault.policy_scanner
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Policy and manifest scanner evaluating zero-trust vault rules LH-VAULT-001 to 010."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from lh_secret_vault.models import (
    RULES_REGISTRY,
    FindingSeverity,
    VaultCategory,
    VaultFinding,
    VaultReport,
)
from lh_secret_vault.vault_crypto import inspect_secret_envelope, is_weak_cipher

IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
    ".pytest_cache",
}


def find_vault_files(root: Path) -> list[Path]:
    """Discover vault manifests, policy documents, and environment files."""
    if root.is_file():
        return [root]

    matched: list[Path] = []
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue

        name = path.name.lower()
        if (
            name.startswith(".env")
            or name.endswith(".env")
            or ".vault." in name
            or name.startswith("vault")
            or "secret" in name
            or name in {"secrets.json", "secrets.yaml", "secrets.yml"}
        ):
            matched.append(path)
        elif name.endswith((".json", ".yaml", ".yml")):
            # Quick check if content has vault or secrets keywords
            try:
                sample = path.read_text(encoding="utf-8", errors="replace")[:1024].lower()
                if any(k in sample for k in ("vault", "secrets", "envelope", "ciphertext")):
                    matched.append(path)
            except Exception:  # nosec B110
                pass

    return sorted(matched)
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


def scan_env_file(path: Path) -> list[VaultFinding]:
    """Scan .env file for unencrypted credentials (LH-VAULT-001)."""
    findings: list[VaultFinding] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    sec_keywords = ("secret", "password", "token", "key", "auth", "credential", "api_key")
    for idx, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("'\"")

            if any(sk in k.lower() for sk in sec_keywords):
                # Check if unencrypted plaintext
                if not v.startswith("ENC[") and not v.startswith("${") and v:
                    rule_def = RULES_REGISTRY["LH-VAULT-001"]
                    findings.append(
                        VaultFinding(
                            rule_id="LH-VAULT-001",
                            severity=FindingSeverity.CRITICAL,
                            category=VaultCategory.PLAINTEXT_SECRET.value,
                            target=str(path),
                            title=rule_def.title,
                            description=(
                                f"Environment variable '{k}' stores unencrypted plaintext "
                                f"credential without envelope encryption"
                            ),
                            remediation=rule_def.remediation,
                            secret_key=k,
                            line_number=idx,
                            snippet=f"{k}=...",
                        )
                    )
    return findings
    # --------------------------------------------------------------------------
    # --- Rule LH-VAULT-010: Missing Secret Governance Metadata (LOW) ---
    # Evaluates security posture against missing secret governance metadata.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def scan_manifest_structure(data: dict[str, Any], path: Path) -> list[VaultFinding]:
    """Evaluate vault manifest data for LH-VAULT-001 through LH-VAULT-010."""
    findings: list[VaultFinding] = []

    # 1. LH-VAULT-003: Hardcoded Master Key or KMS Key Material
    for k_name in ("master_key", "raw_key", "private_key", "passphrase", "kms_secret_key"):
        val = data.get(k_name)
        if isinstance(val, str) and val.strip() and not val.startswith("${"):
            if not val.startswith("arn:aws:kms:") and not val.startswith("projects/"):
                rule_def = RULES_REGISTRY["LH-VAULT-003"]
                findings.append(
                    VaultFinding(
                        rule_id="LH-VAULT-003",
                        severity=FindingSeverity.CRITICAL,
                        category=VaultCategory.KEY_MANAGEMENT.value,
                        target=str(path),
                        title=rule_def.title,
                        description=(
                            f"Hardcoded cryptographic key material in manifest field '{k_name}'"
                        ),
                        remediation=rule_def.remediation,
                        secret_key=k_name,
                        snippet=f"{k_name}: [REDACTED]",
                    )
                )

    # 2. LH-VAULT-002: Weak Cipher in Manifest Config
    cipher_cfg = str(data.get("cipher") or data.get("algorithm") or "")
    if cipher_cfg and is_weak_cipher(cipher_cfg):
        rule_def = RULES_REGISTRY["LH-VAULT-002"]
        findings.append(
            VaultFinding(
                rule_id="LH-VAULT-002",
                severity=FindingSeverity.CRITICAL,
                category=VaultCategory.CRYPTOGRAPHY.value,
                target=str(path),
                title=rule_def.title,
                description=f"Vault configures deprecated or weak cipher '{cipher_cfg}'",
                remediation=rule_def.remediation,
                snippet=f"cipher: {cipher_cfg}",
            )
        )

    # 3. LH-VAULT-004: Permissive file permissions in config
    for perm_key in ("file_mode", "chmod", "permissions"):
        if perm_key in data:
            perm_val = str(data[perm_key])
            if any(bad in perm_val for bad in ("0644", "0777", "0666", "777", "666", "644")):
                rule_def = RULES_REGISTRY["LH-VAULT-004"]
                findings.append(
                    VaultFinding(
                        rule_id="LH-VAULT-004",
                        severity=FindingSeverity.HIGH,
                        category=VaultCategory.ACCESS_CONTROL.value,
                        target=str(path),
                        title=rule_def.title,
                        description=(
                            f"Manifest configures overly permissive file mode '{perm_val}' "
                            f"(allows non-owner access)"
                        ),
                        remediation=rule_def.remediation,
                        snippet=f"{perm_key}: {perm_val}",
                    )
                )

    # 4. LH-VAULT-006: Insecure Runtime Process Secret Injection
    injection_cfg = data.get("injection") or data.get("runtime") or {}
    if isinstance(injection_cfg, dict):
        mode = str(injection_cfg.get("mode") or injection_cfg.get("method") or "").lower()
        if mode in {"cli_args", "command_line", "cmdline", "argv"}:
            rule_def = RULES_REGISTRY["LH-VAULT-006"]
            findings.append(
                VaultFinding(
                    rule_id="LH-VAULT-006",
                    severity=FindingSeverity.HIGH,
                    category=VaultCategory.RUNTIME_INJECTION.value,
                    target=str(path),
                    title=rule_def.title,
                    description=(
                        "Secrets injected via CLI arguments, exposed in /proc/<pid>/cmdline"
                    ),
                    remediation=rule_def.remediation,
                    snippet=f"mode: {mode}",
                )
            )
        if injection_cfg.get("core_dumps_allowed") is True:
            rule_def = RULES_REGISTRY["LH-VAULT-006"]
            findings.append(
                VaultFinding(
                    rule_id="LH-VAULT-006",
                    severity=FindingSeverity.HIGH,
                    category=VaultCategory.RUNTIME_INJECTION.value,
                    target=str(path),
                    title=rule_def.title,
                    description="Process core dumps enabled during secret handling in memory",
                    remediation=rule_def.remediation,
                    snippet="core_dumps_allowed: true",
                )
            )
        if injection_cfg.get("write_temp_files") is True:
            rule_def = RULES_REGISTRY["LH-VAULT-006"]
            findings.append(
                VaultFinding(
                    rule_id="LH-VAULT-006",
                    severity=FindingSeverity.HIGH,
                    category=VaultCategory.RUNTIME_INJECTION.value,
                    target=str(path),
                    title=rule_def.title,
                    description="Runtime writes unencrypted plaintext secret temp files to disk",
                    remediation=rule_def.remediation,
                    snippet="write_temp_files: true",
                )
            )

    # 5. LH-VAULT-008: Wildcard or overly broad identity scope
    access_cfg = (
        data.get("access_policy") or data.get("workload_identity") or data.get("access") or {}
    )
    if isinstance(access_cfg, dict):
        allowed_procs = access_cfg.get("allowed_processes") or []
        allowed_users = access_cfg.get("allowed_users") or []
        namespaces = access_cfg.get("namespaces") or []
        has_wildcard = (
            "*" in allowed_procs
            or "ALL" in allowed_procs
            or "*" in allowed_users
            or "*" in namespaces
        )
        if has_wildcard:
            rule_def = RULES_REGISTRY["LH-VAULT-008"]
            findings.append(
                VaultFinding(
                    rule_id="LH-VAULT-008",
                    severity=FindingSeverity.HIGH,
                    category=VaultCategory.IDENTITY_BINDING.value,
                    target=str(path),
                    title=rule_def.title,
                    description="Wildcard '*' identity binding grants all workloads secret access",
                    remediation=rule_def.remediation,
                    snippet="allowed_processes: ['*']",
                )
            )

    # 6. LH-VAULT-009: Secret Access Audit Logging Disabled
    audit_cfg = data.get("audit") or data.get("audit_logging")
    if audit_cfg is False or data.get("audit_enabled") is False or audit_cfg is None:
        rule_def = RULES_REGISTRY["LH-VAULT-009"]
        findings.append(
            VaultFinding(
                rule_id="LH-VAULT-009",
                severity=FindingSeverity.MEDIUM,
                category=VaultCategory.OBSERVABILITY.value,
                target=str(path),
                title=rule_def.title,
                description="Audit logging is disabled or unconfigured for secret access events",
                remediation=rule_def.remediation,
                snippet="audit_logging: false",
            )
        )

    # 7. Secrets collection iteration (LH-VAULT-001, 002, 005, 007, 010)
    secrets_dict = data.get("secrets") or {}
    if not isinstance(secrets_dict, dict):
        secrets_dict = {}

    for sec_name, sec_val in secrets_dict.items():
        # Inspect individual secret envelope
        envelope_issues = inspect_secret_envelope(sec_val)
        for rule_id, msg in envelope_issues:
            rule_def = RULES_REGISTRY[rule_id]
            findings.append(
                VaultFinding(
                    rule_id=rule_id,
                    severity=rule_def.severity,
                    category=rule_def.category,
                    target=str(path),
                    title=rule_def.title,
                    description=f"Secret '{sec_name}': {msg}",
                    remediation=rule_def.remediation,
                    secret_key=sec_name,
                    snippet=f"{sec_name}: ...",
                )
            )

        # LH-VAULT-005: Expiration and Rotation Policy
        if isinstance(sec_val, dict):
            # Check expiration
            exp_str = sec_val.get("expires_at")
            if exp_str:
                try:
                    exp_dt = datetime.fromisoformat(str(exp_str).replace("Z", "+00:00"))
                    now = datetime.now(UTC)
                    if exp_dt < now:
                        rule_def = RULES_REGISTRY["LH-VAULT-005"]
                        findings.append(
                            VaultFinding(
                                rule_id="LH-VAULT-005",
                                severity=FindingSeverity.HIGH,
                                category=VaultCategory.LIFECYCLE.value,
                                target=str(path),
                                title=rule_def.title,
                                description=(
                                    f"Secret '{sec_name}' expired on {exp_str} and requires "
                                    f"immediate revocation and rotation"
                                ),
                                remediation=rule_def.remediation,
                                secret_key=sec_name,
                                snippet=f"expires_at: '{exp_str}'",
                            )
                        )
                except Exception:  # nosec B110
                    pass

            # Check rotation interval
            rotation_days = sec_val.get("rotation_days")
            rotation_enabled = sec_val.get("rotation_enabled", True)
            if rotation_enabled is False or (rotation_days is not None and rotation_days > 90):
                rule_def = RULES_REGISTRY["LH-VAULT-005"]
                findings.append(
                    VaultFinding(
                        rule_id="LH-VAULT-005",
                        severity=FindingSeverity.HIGH,
                        category=VaultCategory.LIFECYCLE.value,
                        target=str(path),
                        title=rule_def.title,
                        description=(
                            f"Secret '{sec_name}' has insecure rotation policy "
                            f"(days: {rotation_days}, enabled: {rotation_enabled})"
                        ),
                        remediation=rule_def.remediation,
                        secret_key=sec_name,
                        snippet=f"rotation_days: {rotation_days}",
                    )
                )

    return findings
    # --------------------------------------------------------------------------
    # --- Rule LH-VAULT-004: Overly Permissive File Mode on Secret Manifest (HIGH) ---
    # Evaluates security posture against overly permissive file mode on secret
    # manifest.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def scan_file_permissions(path: Path) -> list[VaultFinding]:
    """Audit actual filesystem permissions of secret or vault file (LH-VAULT-004)."""
    findings: list[VaultFinding] = []
    try:
        st = path.stat()
        mode = stat.S_IMODE(st.st_mode)
        # Check if group or others have read/write/execute permissions (mode & 0o077 != 0)
        if mode & 0o077 != 0:
            rule_def = RULES_REGISTRY["LH-VAULT-004"]
            findings.append(
                VaultFinding(
                    rule_id="LH-VAULT-004",
                    severity=FindingSeverity.HIGH,
                    category=VaultCategory.ACCESS_CONTROL.value,
                    target=str(path),
                    title=rule_def.title,
                    description=(
                        f"Secret store file permissions are {oct(mode)} (wider than 0600, "
                        f"granting group/world access)"
                    ),
                    remediation=rule_def.remediation,
                    snippet=f"mode: {oct(mode)}",
                )
            )
    except OSError:
        pass
    return findings


def scan_vault_file(path: Path) -> list[VaultFinding]:
    """Scan an individual vault manifest, policy, or .env file."""
    findings: list[VaultFinding] = []

    # Check file permissions on disk
    findings.extend(scan_file_permissions(path))

    # Check if .env file
    if path.name.startswith(".env") or path.name.endswith(".env"):
        findings.extend(scan_env_file(path))
        return findings

    # Parse JSON or YAML
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix.lower() in {".json"}:
            data = json.loads(content)
        else:
            data = yaml.safe_load(content)

        if isinstance(data, dict):
            findings.extend(scan_manifest_structure(data, path))
    except Exception:  # nosec B110
        pass

    return findings


def scan_vault_target(target: Path) -> VaultReport:
    """Scan a file or directory tree for vault files and aggregate findings."""
    vault_files = find_vault_files(target)
    all_findings: list[VaultFinding] = []

    for vf in vault_files:
        all_findings.extend(scan_vault_file(vf))

    return VaultReport(
        target=str(target),
        files_scanned=len(vault_files),
        vault_manifests_analyzed=len(vault_files),
        findings_count=len(all_findings),
        findings=all_findings,
    )
