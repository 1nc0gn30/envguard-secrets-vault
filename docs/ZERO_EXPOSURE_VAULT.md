# EnvGuard Zero-Exposure Vault Architecture & Cryptographic Specification

This document details the cryptographic principles, envelope format, threat model, and execution engine powering **EnvGuard's Zero-Exposure Encrypted Vault**.

---

## 🔐 Cryptographic Primitives & Specifications

EnvGuard is built exclusively with NIST-approved, industry-standard cryptographic algorithms:

| Component | Standard Primitive | Specification / Parameters |
| :--- | :--- | :--- |
| **Symmetric Cipher** | `AES-256-CTR-HMAC-SHA256` | NIST FIPS-197 AES-256-CTR, 128-bit (16-byte) random counter IV, 256-bit (32-byte) HMAC-SHA256 authentication tag |
| **Auxiliary Stdlib Stream Cipher** | `HMAC-SHA256-CTR` (`vault.py`) | Pure-stdlib HMAC-SHA256 counter-mode keystream (`EncryptedVault`, `-----BEGIN ENVGUARD VAULT v1-----`) with 16-byte salt/nonce and 32-byte EtM tag |
| **Key Derivation (KDF)** | `PBKDF2-HMAC-SHA256` | 100,000+ iterations (Web Crypto & `vault.py`), 600,000 iterations (CLI `mcp_server.py`), 128-bit salt (512-bit key material split into 256-bit encryption key + 256-bit MAC key) |
| **Random Number Generation** | CSPRNG | `os.urandom` (Python) / `crypto.getRandomValues` (Web Crypto) |
| **Payload Envelope** | JSON & ASCII Armor | Self-describing, deterministic base64 / armored fields |

---

## 📦 Envelope Schema Specification (`envguard-vault-v1`)

```json
{
  "$schema": "https://envguard.dev/schemas/vault-v1.json",
  "version": 1,
  "format": "envguard-vault-v1",
  "cipher": "AES-256-CTR-HMAC-SHA256",
  "kdf": "PBKDF2-HMAC-SHA256",
  "kdf_iterations": 100000,
  "salt": "<base64-encoded 16 bytes>",
  "iv": "<base64-encoded 16 bytes>",
  "ciphertext": "<base64-encoded encrypted payload>",
  "tag": "<base64-encoded 32 bytes HMAC-SHA256 auth tag>",
  "created_at": "2026-09-16T18:30:00Z",
  "key_count": 9
}
```

### Integrity & Tamper Detection
EnvGuard utilizes an **Encrypt-then-MAC (EtM)** architecture combining NIST FIPS-197 AES-256-CTR with HMAC-SHA256. If an adversary modifies even a single bit of the `ciphertext`, `iv`, `salt`, or `tag`, constant-time HMAC verification fails during `vault_decrypt()` and execution immediately aborts before any unverified plaintext is processed.

---

## ⚙️ Zero-Disk Execution Engine (`envguard vault run`)

Traditional secret managers frequently write decrypted `.env` files to `/tmp` or the project root before launching a command. This exposes credentials to:
1. Disk forensic recovery.
2. Accidental inclusion in git commits or Docker build contexts.
3. Other unprivileged processes inspecting `/tmp`.

EnvGuard completely bypasses disk storage using **direct process environment inheritance**:

```mermaid
flowchart TD
    A["secrets.vault on Disk"] -->|1. Read Ciphertext| B["EnvGuard Process"]
    C["Master Password / Keyring"] -->|2. Derive AES Key| B
    B -->|3. Decrypt in Ephemeral Memory| D["Plaintext Key-Value Map in RAM"]
    D -->|4. Copy to Child Environment Block| E["Target Subprocess (Node.js / Python / Binary)"]
    D -.->|5. Memory Overwritten & Cleared| F["Garbage Collector / Zeroed"]
    E -->|6. Runs in isolated process space| G["Production Execution"]
```

---

## 🛡️ Threat Model & Security Properties

### Protected Against:
- **Accidental Repository Commits:** `.vault` files are fully encrypted with AES-256-CTR-HMAC-SHA256 and safe for version control.
- **Client-Side Bundle Leaks:** Detects frontend framework prefix misuse (e.g. `NEXT_PUBLIC_`) before production builds.
- **Disk Forensics:** Secrets are injected directly into OS process environments and never touch storage drives.
- **Tampering & Bit-Flipping:** HMAC-SHA256 256-bit authentication tags ensure mathematical tamper evidence.
- **Offline Dictionary Attacks:** High-iteration PBKDF2-HMAC-SHA256 makes brute-force attacks computationally prohibitive.

### Out of Scope:
- Compromised root/kernel-level OS with memory dumping tools attached to the running child process.
- Stolen master password via keylogger.

---

## 📊 Comparison Matrix

| Feature | EnvGuard Vault | HashiCorp Vault | Doppler | dotenv-vault |
| :--- | :--- | :--- | :--- | :--- |
| **Self-Contained (0 Servers)** | ✅ Yes (Local/Git) | ❌ Requires Daemon | ❌ Cloud Only | ❌ Cloud Backend |
| **Zero Disk Write (`vault run`)** | ✅ Yes | ✅ Yes (with agent) | ✅ Yes | ❌ Writes to disk |
| **Native Web Studio UI** | ✅ 100% Client-side | ⚠️ Server UI | ⚠️ SaaS Web | ❌ CLI only |
| **AI Agent MCP Integration** | ✅ Built-in 6 Tools | ❌ Manual plugin | ❌ Third party | ❌ No |
| **Entropy & Prefix Auditor** | ✅ Built-in 50+ | ❌ No | ❌ No | ❌ No |
| **Air-Gapped / Offline** | ✅ 100% Offline | ⚠️ Self-hosted | ❌ No | ❌ No |
