# Encrypted Vault Workflow Example

This example demonstrates the end-to-end workflow for managing production secrets using **EnvGuard's Zero-Exposure Encrypted Vault** (`.vault` format).

---

## 🛡️ Architecture & Security Model

EnvGuard uses **envelope encryption** with industry-standard primitives:
- **Key Derivation:** `PBKDF2-HMAC-SHA256` with 100,000+ iterations and a 16-byte cryptographically secure random salt.
- **Authenticated Encryption:** `AES-256-GCM` (Galois/Counter Mode) with a 12-byte random initialization vector (IV) and a 16-byte authentication tag (`tag`).
- **Tamper Evident:** Any modification to the ciphertext, IV, salt, or tag causes decryption to immediately abort before any plaintext is parsed.
- **Zero Disk Exposure:** Decrypted secrets remain in ephemeral process memory or are piped directly into child process environment blocks (`envguard vault run`).

---

## 📂 Vault File Structure (`sample.vault`)

An EnvGuard `.vault` file is a deterministic, self-describing JSON document that is safe to store in version control:

```json
{
  "version": 1,
  "format": "envguard-vault-v1",
  "cipher": "AES-256-GCM",
  "kdf": "PBKDF2-HMAC-SHA256",
  "kdf_iterations": 100000,
  "salt": "RW52R3VhcmRTYWx0MjAyNg==",
  "iv": "VmF1bHRJVjIwMjYh",
  "ciphertext": "...",
  "tag": "1aqQqmS4RYNb5fxaunFpYQ==",
  "created_at": "2026-09-16T18:30:00Z",
  "key_count": 9
}
```

> **Demo Vault Credentials:**
> - Vault File: `examples/encrypted-vault-workflow/sample.vault`
> - Master Password: `envguard-demo-password-2026!`

---

## 🚀 CLI Commands & Workflow

### 1. Encrypting a Plaintext `.env` File
Create a new encrypted vault from an existing `.env` file:

```bash
# Interactive password prompt
envguard vault create .env.production --output production.vault

# Or provide password via environment variable (ideal for CI/CD)
export ENVGUARD_VAULT_PASSWORD="your-strong-master-password"
envguard vault create .env.production --output production.vault
```

---

### 2. Inspecting Vault Metadata & Contents
View vault summary without revealing raw values, or view full in-memory decrypted key-value pairs:

```bash
# View metadata only (safe for logs)
envguard vault info examples/encrypted-vault-workflow/sample.vault

# View decrypted keys (masked by default)
envguard vault view examples/encrypted-vault-workflow/sample.vault --password "envguard-demo-password-2026!"

# View unmasked
envguard vault view examples/encrypted-vault-workflow/sample.vault --password "envguard-demo-password-2026!" --unmask
```

---

### 3. Zero-Disk Runtime Secret Injection (`envguard vault run`)
Inject decrypted secrets directly into your application runtime environment without ever writing a `.env` file to disk:

```bash
# Python Web App
envguard vault run --vault sample.vault --password "envguard-demo-password-2026!" -- uvicorn app.main:app --port 8080

# Node.js / Next.js
envguard vault run --vault sample.vault --password "envguard-demo-password-2026!" -- npm start

# Go / Rust / Docker
envguard vault run --vault sample.vault --password "envguard-demo-password-2026!" -- ./my-server-binary
```

---

### 4. In-Memory Decryption to File (When Necessary)
If an external tool requires a temporary file:

```bash
envguard vault decrypt sample.vault --output .env.local --password "envguard-demo-password-2026!"
```

---

## 🐍 Python Decryption Verification

You can verify and decrypt `sample.vault` using standard Python `cryptography` in 10 lines:

```python
import json, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Load vault JSON
with open("examples/encrypted-vault-workflow/sample.vault") as f:
    vault = json.load(f)

# 2. Derive 256-bit key from password
password = b"envguard-demo-password-2026!"
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=base64.b64decode(vault["salt"]),
    iterations=vault["kdf_iterations"],
)
key = kdf.derive(password)

# 3. Decrypt with AES-256-GCM
aesgcm = AESGCM(key)
iv = base64.b64decode(vault["iv"])
ciphertext = base64.b64decode(vault["ciphertext"]) + base64.b64decode(vault["tag"])
plaintext = aesgcm.decrypt(iv, ciphertext, None).decode("utf-8")

print(plaintext)
```

---

## 🌐 Web Studio In-Browser Decryption

You can also drag-and-drop `sample.vault` into the **EnvGuard Secrets Studio** UI (`public/index.html`) under the **Zero-Exposure Encrypted Vault** tab to inspect and decrypt using the Web Crypto API.
