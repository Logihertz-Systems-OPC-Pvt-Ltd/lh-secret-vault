# ==============================================================================
# Product:       lh-secret-vault (lh-vault)
# Module:        tests.test_vault_crypto
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for vault cryptographic validation and envelope verification."""

from __future__ import annotations

from lh_secret_vault.vault_crypto import (
    check_kdf_parameters,
    inspect_secret_envelope,
    is_approved_cipher,
    is_weak_cipher,
    parse_enc_wrapper,
    validate_tag_and_iv,
)


def test_cipher_evaluation() -> None:
    """Test identifying weak vs approved AEAD ciphers."""
    assert is_weak_cipher("AES-ECB")
    assert is_weak_cipher("DES")
    assert is_weak_cipher("3DES")
    assert is_weak_cipher("RC4")
    assert not is_weak_cipher("AES-256-GCM")

    assert is_approved_cipher("AES-256-GCM")
    assert is_approved_cipher("ChaCha20-Poly1305")
    assert not is_approved_cipher("AES-ECB")


def test_kdf_parameter_checks() -> None:
    """Test checking KDF algorithm and iteration threshold."""
    issues = check_kdf_parameters("MD5", 50000)
    assert len(issues) == 2
    assert any("Insecure KDF" in i for i in issues)
    assert any("Insufficient KDF iterations" in i for i in issues)

    compliant = check_kdf_parameters("SHA256", 600000)
    assert len(compliant) == 0


def test_parse_enc_wrapper() -> None:
    """Test parsing ENC[CIPHER,data:...,iv:...,tag:...] envelope strings."""
    raw = "ENC[AES256_GCM,data:YWJj,iv:MTIz,tag:NDU2,key_id:kms-1]"
    parsed = parse_enc_wrapper(raw)
    assert parsed["cipher"] == "AES256_GCM"
    assert parsed["data"] == "YWJj"
    assert parsed["iv"] == "MTIz"
    assert parsed["tag"] == "NDU2"
    assert parsed["key_id"] == "kms-1"


def test_validate_tag_and_iv() -> None:
    """Test validating authentication tag and IV byte lengths."""
    # 12-byte IV (16 base64 chars), 16-byte tag (24 base64 chars)
    valid_iv = "MTIzNDU2Nzg5MDEy"
    valid_tag = "MTIzNDU2Nzg5MDEyMzQ1Ng=="
    ok, _ = validate_tag_and_iv(valid_iv, valid_tag)
    assert ok

    # Missing IV
    bad_iv, msg = validate_tag_and_iv(None, valid_tag)
    assert not bad_iv
    assert "Missing initialization vector" in msg

    # Truncated tag
    bad_tag, msg = validate_tag_and_iv(valid_iv, "dG9vc2hvcnQ=")
    assert not bad_tag
    assert "Truncated authentication tag" in msg


def test_inspect_secret_envelope_plaintext_string() -> None:
    """Test inspecting a raw plaintext secret string triggers LH-VAULT-001."""
    findings = inspect_secret_envelope("SuperPlaintextPassword123")
    assert len(findings) == 1
    assert findings[0][0] == "LH-VAULT-001"


def test_inspect_secret_envelope_weak_cipher_string() -> None:
    """Test inspecting ENC[AES_ECB,...] triggers LH-VAULT-002."""
    raw = "ENC[AES_ECB,data:YWJj,iv:MTIzNDU2Nzg5MDEy,tag:MTIzNDU2Nzg5MDEyMzQ1Ng==,key_id:k1]"
    findings = inspect_secret_envelope(raw)
    rules = [f[0] for f in findings]
    assert "LH-VAULT-002" in rules


def test_inspect_secret_envelope_dict_unencrypted() -> None:
    """Test inspecting dictionary marked encrypted: false triggers LH-VAULT-001."""
    entry = {"encrypted": False, "plaintext": "secret-value"}
    findings = inspect_secret_envelope(entry)
    assert any(f[0] == "LH-VAULT-001" for f in findings)
