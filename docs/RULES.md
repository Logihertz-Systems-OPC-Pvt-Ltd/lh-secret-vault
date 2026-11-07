# Security Rules Reference: lh-secret-vault

An enterprise secret vault manifest & envelope encryption auditor developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-secret-vault`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-VAULT-001` | `CRITICAL` | Secret Exposure | Unencrypted Plaintext Secret in Vault Manifest |
| `LH-VAULT-002` | `CRITICAL` | Cryptography | Weak or Deprecated Encryption Cipher / KDF |
| `LH-VAULT-003` | `CRITICAL` | Key Management | Hardcoded Master Key or Raw KMS Key Material |
| `LH-VAULT-004` | `HIGH` | Filesystem Security | Overly Permissive File Mode on Secret Manifest |
| `LH-VAULT-005` | `HIGH` | Secret Governance | Expired Secret or Missing Rotation Policy |
| `LH-VAULT-006` | `HIGH` | Runtime Security | Insecure Runtime Secret Injection Vector |
| `LH-VAULT-007` | `MEDIUM` | Cryptography | Missing or Truncated Cryptographic Authentication Tag |
| `LH-VAULT-008` | `HIGH` | Access Control | Wildcard or Overly Broad Workload Identity Binding |
| `LH-VAULT-009` | `MEDIUM` | Audit Logging | Secret Access Audit Logging Disabled in Vault Config |
| `LH-VAULT-010` | `LOW` | Governance | Missing Secret Governance Metadata |

---

## Granular Rule Specifications

### `LH-VAULT-001`: Unencrypted Plaintext Secret in Vault Manifest

- **Severity**: `CRITICAL`
- **Category**: `Secret Exposure`
- **Description**: Unencrypted secret value or plaintext password stored in vault manifest or .env.vault file.
- **Remediation**: Encrypt secret payload using authenticated AEAD encryption (AES-256-GCM) or KMS envelope encryption.

---

### `LH-VAULT-002`: Weak or Deprecated Encryption Cipher / KDF

- **Severity**: `CRITICAL`
- **Category**: `Cryptography`
- **Description**: Vault uses deprecated cipher (DES, 3DES, RC4, AES-ECB) or weak KDF (MD5, SHA1).
- **Remediation**: Migrate to AES-256-GCM or ChaCha20-Poly1305 with Argon2id or PBKDF2-HMAC-SHA256 (>= 600,000 iterations).

---

### `LH-VAULT-003`: Hardcoded Master Key or Raw KMS Key Material

- **Severity**: `CRITICAL`
- **Category**: `Key Management`
- **Description**: Raw KMS private key material or master passphrase hardcoded in manifest.
- **Remediation**: Delegate master key protection to hardware-backed KMS (AWS KMS, GCP Cloud KMS, HashiCorp Vault transit).

---

### `LH-VAULT-004`: Overly Permissive File Mode on Secret Manifest

- **Severity**: `HIGH`
- **Category**: `Filesystem Security`
- **Description**: Vault configuration or secret file has permissions looser than 0600.
- **Remediation**: Enforce restrictive file permissions (chmod 600) on all local vault manifests.

---

### `LH-VAULT-005`: Expired Secret or Missing Rotation Policy

- **Severity**: `HIGH`
- **Category**: `Secret Governance`
- **Description**: Secret has passed expires_at date or lacks automated rotation configuration.
- **Remediation**: Configure automated secret rotation schedule (<= 90 days) and renew expired credentials.

---

### `LH-VAULT-006`: Insecure Runtime Secret Injection Vector

- **Severity**: `HIGH`
- **Category**: `Runtime Security`
- **Description**: Secrets passed via command-line arguments or cleartext environment variables in container specs.
- **Remediation**: Inject secrets via in-memory tmpfs files or dedicated secret CSI volume drivers.

---

### `LH-VAULT-007`: Missing or Truncated Cryptographic Authentication Tag

- **Severity**: `MEDIUM`
- **Category**: `Cryptography`
- **Description**: Encrypted payload lacks HMAC or GCM authentication tag, risking ciphertext tampering.
- **Remediation**: Enforce AEAD cipher modes (AES-GCM) that guarantee both confidentiality and integrity authentication.

---

### `LH-VAULT-008`: Wildcard or Overly Broad Workload Identity Binding

- **Severity**: `HIGH`
- **Category**: `Access Control`
- **Description**: Vault access policy grants read access to all workloads via wildcard subject binding.
- **Remediation**: Scope vault access policies strictly to specific workload identities or service accounts.

---

### `LH-VAULT-009`: Secret Access Audit Logging Disabled in Vault Config

- **Severity**: `MEDIUM`
- **Category**: `Audit Logging`
- **Description**: Audit logging disabled or access telemetry missing in vault configuration.
- **Remediation**: Enable comprehensive audit device logging for all secret read and write operations.

---

### `LH-VAULT-010`: Missing Secret Governance Metadata

- **Severity**: `LOW`
- **Category**: `Governance`
- **Description**: Secret entry lacks key_id, version, owner, or description metadata tags.
- **Remediation**: Require metadata tags (owner, rotation_interval, description) on all managed vault secrets.

---
