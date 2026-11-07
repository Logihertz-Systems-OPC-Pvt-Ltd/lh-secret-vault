# ==============================================================================
# Product:       lh-secret-vault (lh-vault)
# Module:        src.lh_secret_vault.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and rule definitions for lh-secret-vault."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity ratings for vault security audit findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparison."""
        ranks = {
            FindingSeverity.CRITICAL: 4,
            FindingSeverity.HIGH: 3,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
        }
        return ranks.get(self, 0)

    @classmethod
    def from_string(cls, val: str) -> FindingSeverity:
        """Convert string to FindingSeverity case-insensitively."""
        normalized = val.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.LOW

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


class VaultCategory(StrEnum):
    """Categories of zero-trust secret vault audit findings."""

    PLAINTEXT_SECRET = "Plaintext Secret"  # nosec B105
    CRYPTOGRAPHY = "Cryptography"
    KEY_MANAGEMENT = "Key Management"
    ACCESS_CONTROL = "Access Control"
    LIFECYCLE = "Lifecycle"
    RUNTIME_INJECTION = "Runtime Injection"
    IDENTITY_BINDING = "Identity Binding"
    OBSERVABILITY = "Observability"
    GOVERNANCE = "Governance"


@dataclass
class VaultFinding:
    """Security finding detected during vault and policy inspection."""

    rule_id: str
    severity: FindingSeverity
    category: str
    target: str
    title: str
    description: str
    remediation: str
    secret_key: str | None = None
    line_number: int | None = None
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to dictionary format."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category,
            "target": self.target,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "secret_key": self.secret_key,
            "line_number": self.line_number,
            "snippet": self.snippet,
        }


@dataclass
class VaultReport:
    """Consolidated audit report across scanned vault manifests and policies."""

    target: str
    files_scanned: int
    vault_manifests_analyzed: int
    findings_count: int
    findings: list[VaultFinding]
    summary: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.summary:
            self.summary = {
                "critical": sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == FindingSeverity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == FindingSeverity.LOW),
            }


@dataclass
class VaultRuleDefinition:
    """Specification of a vault audit detection rule."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    remediation: str


RULES_REGISTRY: dict[str, VaultRuleDefinition] = {
    "LH-VAULT-001": VaultRuleDefinition(
        rule_id="LH-VAULT-001",
        title="Unencrypted Plaintext Secret in Vault Manifest",
        severity=FindingSeverity.CRITICAL,
        category=VaultCategory.PLAINTEXT_SECRET.value,
        description=(
            "Unencrypted plaintext secret stored in vault manifest or .env file without "
            "authenticated envelope encryption (missing ENC[...] wrapper or encrypted: false)."
        ),
        remediation="Wrap secret values with envelope encryption using KMS or local master key.",
    ),
    "LH-VAULT-002": VaultRuleDefinition(
        rule_id="LH-VAULT-002",
        title="Weak / Deprecated Cipher or KDF Parameters",
        severity=FindingSeverity.CRITICAL,
        category=VaultCategory.CRYPTOGRAPHY.value,
        description=(
            "Weak or deprecated encryption cipher or key derivation function configured "
            "(e.g., AES-ECB, DES, 3DES, RC4, MD5, SHA1, or PBKDF2 iterations < 100000)."
        ),
        remediation=(
            "Configure AES-256-GCM or ChaCha20-Poly1305 with Argon2id or PBKDF2 >= 600,000 "
            "iterations."
        ),
    ),
    "LH-VAULT-003": VaultRuleDefinition(
        rule_id="LH-VAULT-003",
        title="Hardcoded Master Key or KMS Key Material",
        severity=FindingSeverity.CRITICAL,
        category=VaultCategory.KEY_MANAGEMENT.value,
        description=(
            "Hardcoded master key, passphrase, or raw KMS key material embedded directly "
            "inside the vault manifest or policy configuration."
        ),
        remediation="Reference external KMS Key ARN, HSM slot, or TPM-backed key provider.",
    ),
    "LH-VAULT-004": VaultRuleDefinition(
        rule_id="LH-VAULT-004",
        title="Overly Permissive File Permissions on Secret Store",
        severity=FindingSeverity.HIGH,
        category=VaultCategory.ACCESS_CONTROL.value,
        description=(
            "Overly permissive file mode configured or detected on secret store, keyfile, or "
            "socket (permissions wider than 0600/0400, or group/world access enabled)."
        ),
        remediation="Restrict secret store file permissions strictly to 0600 or 0400 (owner only).",
    ),
    "LH-VAULT-005": VaultRuleDefinition(
        rule_id="LH-VAULT-005",
        title="Expired Secret or Missing Rotation Policy",
        severity=FindingSeverity.HIGH,
        category=VaultCategory.LIFECYCLE.value,
        description=(
            "Expired secret or missing rotation policy (expires_at timestamp in the past, "
            "rotation_days > 90, or rotation_enabled: false)."
        ),
        remediation=(
            "Enforce automatic secret rotation <= 90 days and revoke expired credentials."
        ),
    ),
    "LH-VAULT-006": VaultRuleDefinition(
        rule_id="LH-VAULT-006",
        title="Insecure Runtime Process Secret Injection Vector",
        severity=FindingSeverity.HIGH,
        category=VaultCategory.RUNTIME_INJECTION.value,
        description=(
            "Insecure runtime secret injection vector (passing secrets via CLI arguments exposed "
            "in /proc/<pid>/cmdline, writing plaintext temp files, or core_dumps_allowed: true)."
        ),
        remediation=(
            "Inject secrets via RAM-backed anonymous pipes, tmpfs, or environment variables."
        ),
    ),
    "LH-VAULT-007": VaultRuleDefinition(
        rule_id="LH-VAULT-007",
        title="Truncated / Missing Cryptographic Auth Tag or IV",
        severity=FindingSeverity.MEDIUM,
        category=VaultCategory.CRYPTOGRAPHY.value,
        description=(
            "Missing or truncated cryptographic integrity authentication tag, nonce/IV, or "
            "HMAC signature on encrypted secret entry."
        ),
        remediation=(
            "Provide full 128-bit authentication tag and standard 96-bit initialization vector."
        ),
    ),
    "LH-VAULT-008": VaultRuleDefinition(
        rule_id="LH-VAULT-008",
        title="Wildcard or Overly Broad Workload Identity Scope",
        severity=FindingSeverity.HIGH,
        category=VaultCategory.IDENTITY_BINDING.value,
        description=(
            "Wildcard or overly broad workload identity binding (allowed_processes: ['*'], "
            "allowed_users: ['*'], or unrestricted namespace scope)."
        ),
        remediation=(
            "Bind secret access strictly to authenticated SPIFFE IDs, mTLS, or specific UIDs."
        ),
    ),
    "LH-VAULT-009": VaultRuleDefinition(
        rule_id="LH-VAULT-009",
        title="Secret Access Audit Logging Disabled",
        severity=FindingSeverity.MEDIUM,
        category=VaultCategory.OBSERVABILITY.value,
        description=(
            "Secret access audit logging or tamper-evident telemetry disabled "
            "(audit_logging: false or missing audit sink configuration)."
        ),
        remediation="Enable structured tamper-resistant access audit logging to SIEM or syslog.",
    ),
    "LH-VAULT-010": VaultRuleDefinition(
        rule_id="LH-VAULT-010",
        title="Missing Secret Governance Metadata Tags",
        severity=FindingSeverity.LOW,
        category=VaultCategory.GOVERNANCE.value,
        description=(
            "Missing secret governance metadata (missing key_id, version, owner, or environment "
            "classification tag)."
        ),
        remediation=("Tag all secret definitions with key_id, version, owner, and classification."),
    ),
}
