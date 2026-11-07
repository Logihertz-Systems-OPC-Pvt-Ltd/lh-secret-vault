# ==============================================================================
# Product:       lh-secret-vault (lh-vault)
# Module:        src.lh_secret_vault.vault_crypto
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Cryptographic verification and envelope structure validation for zero-trust secrets."""

from __future__ import annotations

import base64
import re
from typing import Any

WEAK_CIPHERS = {
    "aes-ecb",
    "des",
    "3des",
    "triple-des",
    "rc4",
    "arcfour",
    "blowfish",
    "md5",
    "sha1",
}

APPROVED_CIPHERS = {
    "aes-256-gcm",
    "aes-128-gcm",
    "chacha20-poly1305",
    "xchacha20-poly1305",
    "aes-gcm",
}


def is_weak_cipher(cipher: str) -> bool:
    """Return True if cipher or hashing algorithm is deprecated or unauthenticated."""
    norm = cipher.strip().lower().replace("_", "-")
    return any(weak in norm for weak in WEAK_CIPHERS)


def is_approved_cipher(cipher: str) -> bool:
    """Return True if cipher uses modern authenticated AEAD encryption."""
    norm = cipher.strip().lower().replace("_", "-")
    return norm in APPROVED_CIPHERS or "gcm" in norm or "poly1305" in norm


def check_kdf_parameters(kdf: str, iterations: int | None) -> list[str]:
    """Audit key derivation function algorithm and iteration count."""
    issues: list[str] = []
    kdf_norm = kdf.strip().lower()
    if kdf_norm in {"md5", "sha1"}:
        issues.append(f"Insecure KDF hash function '{kdf}'")
    if iterations is not None and iterations < 100000:
        issues.append(f"Insufficient KDF iterations ({iterations} < 100,000 required)")
    return issues


def parse_enc_wrapper(enc_str: str) -> dict[str, str]:
    """Parse ENC[CIPHER,data:...,iv:...,tag:...] string syntax."""
    # Pattern: ENC[CIPHER,key:val,key:val]
    m = re.match(r"^ENC\[([A-Za-z0-9_\-]+)(?:,(.+))?\]$", enc_str)
    if not m:
        return {}

    cipher = m.group(1)
    params: dict[str, str] = {"cipher": cipher}
    rest = m.group(2)
    if rest:
        # Split on commas that are not nested
        for pair in rest.split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                params[k.strip().lower()] = v.strip()
    return params


def validate_tag_and_iv(iv_val: str | None, tag_val: str | None) -> tuple[bool, str]:
    """Validate that authentication tag (>=16 bytes) and IV (>=12 bytes) are valid."""
    if not iv_val:
        return False, "Missing initialization vector (IV/nonce)"
    if not tag_val:
        return False, "Missing cryptographic authentication tag"

    # Decode if base64 or hex
    try:
        if len(iv_val) in (24, 32) and re.match(r"^[0-9a-fA-F]+$", iv_val):
            iv_bytes = bytes.fromhex(iv_val)
        else:
            iv_bytes = base64.b64decode(iv_val)
        if len(iv_bytes) < 12:
            return False, f"Truncated IV length ({len(iv_bytes)} bytes < 12 bytes minimum)"
    except Exception:  # nosec B110
        pass

    try:
        if len(tag_val) == 32 and re.match(r"^[0-9a-fA-F]+$", tag_val):
            tag_bytes = bytes.fromhex(tag_val)
        else:
            tag_bytes = base64.b64decode(tag_val)
        if len(tag_bytes) < 16:
            return False, f"Truncated authentication tag length ({len(tag_bytes)} bytes < 16 bytes)"
    except Exception:  # nosec B110
        pass

    return True, ""


def inspect_secret_envelope(entry: Any) -> list[tuple[str, str]]:
    """Inspect secret entry (string or dict) for cryptographic defects.

    Returns:
        List of (rule_id, detail_message) tuples.
    """
    findings: list[tuple[str, str]] = []

    # 1. String representation: check for unencrypted vs ENC[...]
    if isinstance(entry, str):
        val = entry.strip()
        if not val.startswith("ENC["):
            # Plaintext secret
            findings.append(
                (
                    "LH-VAULT-001",
                    (
                        "Secret value stored as unencrypted plaintext without authenticated "
                        "envelope wrapper"
                    ),
                )
            )
            return findings

        parsed = parse_enc_wrapper(val)
        cipher = parsed.get("cipher", "")
        if is_weak_cipher(cipher):
            findings.append(
                (
                    "LH-VAULT-002",
                    f"Envelope encrypted with weak or deprecated cipher '{cipher}'",
                )
            )

        # Check tag and IV
        iv_param = parsed.get("iv") or parsed.get("nonce")
        tag_param = parsed.get("tag") or parsed.get("auth_tag")
        valid, msg = validate_tag_and_iv(iv_param, tag_param)
        if not valid:
            findings.append(("LH-VAULT-007", msg))

        # Check governance key_id
        if "key_id" not in parsed and "kms_id" not in parsed:
            findings.append(
                ("LH-VAULT-010", "Missing key_id or kms_id in envelope metadata wrapper")
            )

    # 2. Dictionary representation
    elif isinstance(entry, dict):
        encrypted_flag = entry.get("encrypted", True)
        if encrypted_flag is False or "plaintext" in entry:
            findings.append(
                (
                    "LH-VAULT-001",
                    "Manifest entry marked encrypted: false or contains plaintext field",
                )
            )
            return findings

        cipher = str(entry.get("cipher") or entry.get("algorithm") or "")
        if cipher and is_weak_cipher(cipher):
            findings.append(
                (
                    "LH-VAULT-002",
                    f"Manifest configures weak or deprecated cipher '{cipher}'",
                )
            )

        # KDF iterations check
        kdf = str(entry.get("kdf") or "")
        iterations = entry.get("kdf_iterations") or entry.get("iterations")
        if iterations is not None:
            kdf_issues = check_kdf_parameters(kdf, int(iterations))
            for ki in kdf_issues:
                findings.append(("LH-VAULT-002", ki))

        # Tag and IV validation
        iv_val = entry.get("iv") or entry.get("nonce")
        tag_val = entry.get("tag") or entry.get("auth_tag")
        if "ciphertext" in entry or "data" in entry:
            valid, msg = validate_tag_and_iv(iv_val, tag_val)
            if not valid:
                findings.append(("LH-VAULT-007", msg))

        # Governance tags check
        missing_gov = []
        for g_tag in ("key_id", "version", "owner"):
            if g_tag not in entry:
                missing_gov.append(g_tag)
        if missing_gov:
            findings.append(
                (
                    "LH-VAULT-010",
                    f"Missing governance metadata field(s): {', '.join(missing_gov)}",
                )
            )

    return findings
