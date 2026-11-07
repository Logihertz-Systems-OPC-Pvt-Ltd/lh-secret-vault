# ==============================================================================
# Product:       lh-secret-vault (lh-vault)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Test fixtures and mock vault manifests for lh-secret-vault test suite."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def clean_vault_project(tmp_path: Path) -> Path:
    """Create a fully compliant zero-trust vault repository."""
    proj = tmp_path / "clean_vault"
    proj.mkdir()

    manifest = proj / "vault.json"
    manifest.write_text(
        """{
  "vault_version": "1.0.0",
  "cipher": "AES-256-GCM",
  "file_mode": "0600",
  "audit": {
    "enabled": true,
    "sink": "syslog",
    "tamper_evident": true
  },
  "runtime": {
    "mode": "ram_pipe",
    "core_dumps_allowed": false,
    "write_temp_files": false
  },
  "access_policy": {
    "allowed_processes": ["/usr/bin/app-service"],
    "allowed_users": ["appuser"]
  },
  "secrets": {
    "database_password": {
      "cipher": "AES-256-GCM",
      "ciphertext": "YWJjZGVmZ2hpamtsbW5vcA==",
      "iv": "MTIzNDU2Nzg5MDEy",
      "tag": "MTIzNDU2Nzg5MDEyMzQ1Ng==",
      "key_id": "kms-key-prod-01",
      "version": "1.0",
      "owner": "security-team",
      "expires_at": "2030-01-01T00:00:00Z",
      "rotation_days": 60,
      "rotation_enabled": true
    }
  }
}
""",
        encoding="utf-8",
    )
    # Set compliant file permissions (0600)
    try:
        os.chmod(manifest, 0o600)
    except OSError:
        pass

    return proj


@pytest.fixture
def insecure_env_file(tmp_path: Path) -> Path:
    """Create .env file containing unencrypted plaintext credentials (LH-VAULT-001)."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# Application credentials\n"
        "DB_PASSWORD=SuperSecretPass123!\n"
        "API_KEY=sk_live_9876543210abcdef\n"
        "JWT_SECRET=super-insecure-unencrypted-secret\n",
        encoding="utf-8",
    )
    return env_file


@pytest.fixture
def vulnerable_vault_manifest(tmp_path: Path) -> Path:
    """Create vault manifest triggering LH-VAULT-002, 003, 004, 005, 006, 007, 008, 009, 010."""
    v_file = tmp_path / "insecure.vault.yaml"
    v_file.write_text(
        """vault_name: insecure-cluster-vault
cipher: AES-ECB
master_key: "raw-hex-master-key-deadbeef12345678"
file_mode: "0777"
audit_logging: false
runtime:
  mode: cli_args
  core_dumps_allowed: true
  write_temp_files: true
access_policy:
  allowed_processes:
    - "*"
secrets:
  unencrypted_api_key:
    encrypted: false
    plaintext: "sk_test_1234567890"
  weak_cipher_secret:
    cipher: DES
    kdf: MD5
    kdf_iterations: 1000
    ciphertext: "dGVzdA=="
  truncated_tag_secret:
    cipher: AES-256-GCM
    ciphertext: "dGVzdA=="
    iv: "short"
    tag: "short"
  expired_token:
    cipher: AES-256-GCM
    ciphertext: "dGVzdA=="
    iv: "MTIzNDU2Nzg5MDEy"
    tag: "MTIzNDU2Nzg5MDEyMzQ1Ng=="
    key_id: "key-1"
    version: "1.0"
    owner: "sec"
    expires_at: "2020-01-01T00:00:00Z"
    rotation_days: 180
    rotation_enabled: false
""",
        encoding="utf-8",
    )
    # Set wide permissions (0777)
    try:
        os.chmod(v_file, 0o777)
    except OSError:
        pass

    return v_file
