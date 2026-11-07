# lh-secret-vault

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-secret-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-secret-vault/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise cryptographic secret vault & key policy auditor developed by **Logihertz Systems (OPC) Private Limited**.

Provides local authenticated envelope encryption vault inspection and audits KMS/Vault key rotation policies, KDF iteration counts (PBKDF2/Argon2), static IV/nonce reuse, unsealed master keys, and plaintext secret backups.

---

## Key Features

- **Multi-Vault Schema Auditing**: Ingests HashiCorp Vault manifests, AWS Secrets Manager templates, Azure Key Vault JSON, and `.env.vault` configurations.
- **Envelope Encryption & Cipher Verification**: Flags weak or deprecated encryption algorithms (DES, 3DES, RC4, AES-ECB) and verifies AEAD modes (AES-GCM, ChaCha20-Poly1305).
- **Hardcoded Master Key Detection**: Identifies hardcoded KMS key material, plaintext passphrases, or unencrypted private keys.
- **Access Policy & File Mode Auditing**: Validates restrictive file permissions on local vault files (mode 0600) and detects wildcard access policies.
- **Multi-Format Reporting**: Outputs rich terminal tables, machine-readable JSON, and OASIS SARIF v2.1.0.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-VAULT-001` | `CRITICAL` | Unencrypted plaintext secret stored in vault manifest or .env.vault file |
| `LH-VAULT-002` | `CRITICAL` | Weak or deprecated encryption cipher or key derivation function (DES, 3DES, AES-ECB) |
| `LH-VAULT-003` | `CRITICAL` | Hardcoded master key, passphrase, or raw KMS key material embedded in manifest |
| `LH-VAULT-004` | `HIGH` | Overly permissive file mode configured or detected on secret manifest (> 0600) |
| `LH-VAULT-005` | `HIGH` | Expired secret or missing rotation policy (expires_at timestamp in past or rotation unset) |
| `LH-VAULT-006` | `HIGH` | Insecure runtime secret injection vector (passing secrets via command line or cleartext ENV) |
| `LH-VAULT-007` | `MEDIUM` | Missing or truncated cryptographic integrity authentication tag in encrypted payload |
| `LH-VAULT-008` | `HIGH` | Wildcard or overly broad workload identity binding in secret access policy |
| `LH-VAULT-009` | `MEDIUM` | Secret access audit logging or tamper-evident telemetry disabled in vault config |
| `LH-VAULT-010` | `LOW` | Missing secret governance metadata (missing key_id, version, or description) |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-secret-vault.git
cd lh-secret-vault

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-vault` (also accessible via `lh-vault`, `lh-secret-vault`).

```bash
# Scan a secret vault manifest file
lh-vault scan vault-config.yaml

# Audit a .env.vault file
lh-vault scan .env.vault --format json

# Export findings to OASIS SARIF v2.1.0
lh-vault scan ./secrets/ --format sarif --output vault-results.sarif

# List all secret vault detection rules
lh-vault rules
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
