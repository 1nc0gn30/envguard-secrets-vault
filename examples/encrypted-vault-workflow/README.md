# Encrypted Vault Workflow Example

This example demonstrates the end-to-end workflow for managing production secrets using **EnvGuard's Zero-Exposure Encrypted Vault** (`.vault` format).

---

## 🛡️ Architecture & Security Model

EnvGuard uses **envelope encryption** with industry-standard primitives:
- **Key Derivation:** `PBKDF2-HMAC-SHA256` with 100,000+ iterations and a 16-byte cryptographically secure random salt (deriving 512 bits: 256-bit encryption key + 256-bit MAC key).
- **Authenticated Encryption:** `AES-256-CTR-HMAC-SHA256` (Counter Mode with Encrypt-then-MAC) with a 16-byte random counter vector (`iv`) and a 32-byte HMAC-SHA256 authentication tag (`hmac` / `tag`).
- **Tamper Evident:** Any modification to the ciphertext, IV, salt, or HMAC tag causes decryption to immediately abort before any plaintext is parsed.
- **Zero Disk Exposure:** Decrypted secrets remain in ephemeral process memory or are piped directly into child process environment blocks (`envguard vault run`).

---

## 📂 Vault File Structure (`sample.vault`)

An EnvGuard `.vault` artifact is a deterministic, self-describing ASCII armored envelope (or JSON payload) that is safe to store in version control:

```
-----BEGIN ENVGUARD ENCRYPTED VAULT-----
version: 1
cipher: AES-256-CTR-HMAC-SHA256
kdf: PBKDF2-HMAC-SHA256
iterations: 100000
salt: ff4003763f047def841c54cd3b2f8b4c
iv: 09ba9bf696065f864a5ee842e84b2f72
hmac: 93265507ad063cf99083a354bcb10e59a7fb7726e9e49398fc2a02563389932f
payload:
...
-----END ENVGUARD ENCRYPTED VAULT-----
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

You can verify and decrypt `sample.vault` using `envguard_secrets_vault` or pure Python with `cryptography`:

```python
import hashlib, hmac, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 1. Parse ASCII armored vault envelope
with open("examples/encrypted-vault-workflow/sample.vault") as f:
    text = f.read()

headers, payload_b64 = {}, []
in_payload = False
for line in text.strip().splitlines():
    if line == "payload:":
        in_payload = True
        continue
    if in_payload and not line.startswith("-----"):
        payload_b64.append(line.strip())
    elif ":" in line and not line.startswith("-----"):
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()

salt = bytes.fromhex(headers["salt"])
iv = bytes.fromhex(headers["iv"])
expected_mac = bytes.fromhex(headers["hmac"])
ciphertext = base64.b64decode("".join(payload_b64))

# 2. Derive 512-bit key material (256-bit encryption key + 256-bit MAC key)
password = b"envguard-demo-password-2026!"
key_material = hashlib.pbkdf2_hmac("sha256", password, salt, int(headers.get("iterations", 100000)), dklen=64)
enc_key, mac_key = key_material[:32], key_material[32:64]

# 3. Authenticate-then-Decrypt (EtM verification)
computed_mac = hmac.new(mac_key, salt + iv + ciphertext, hashlib.sha256).digest()
if not hmac.compare_digest(computed_mac, expected_mac):
    raise ValueError("MAC verification failed - vault artifact corrupted or tampered")

decryptor = Cipher(algorithms.AES(enc_key), modes.CTR(iv)).decryptor()
plaintext = (decryptor.update(ciphertext) + decryptor.finalize()).decode("utf-8")
print(plaintext)
```

Or using the EnvGuard Python API directly:
```python
from envguard_secrets_vault.mcp_server import vault_decrypt

with open("examples/encrypted-vault-workflow/sample.vault") as f:
    result = vault_decrypt(f.read(), "envguard-demo-password-2026!")

print(result["decrypted_content"])
```

---

## 🌐 Web Studio In-Browser Decryption

You can also drag-and-drop `sample.vault` into the **EnvGuard Secrets Studio** UI (`public/index.html`) under the **Zero-Exposure Encrypted Vault** tab to inspect and decrypt using the Web Crypto API.
