# EnvGuard Threat Model & Trust Assumptions Verification

This document makes explicit the implicit security assumptions, trust boundaries, and brittle loops across the EnvGuard Secrets Vault implementation.

---

## 🗝️ Core Security & Cryptographic Invariants

| Invariant | Implementation Mechanism | Potential Failure Mode / Brittle Boundary | Verification Status |
| :--- | :--- | :--- | :--- |
| **Tamper-Evident Storage** | AES-256-GCM AEAD Tag (128-bit) | Modifying metadata or ciphertext invalidates tag; envelope version mismatch can trigger parsing divergence. | Verified |
| **Key Derivation Work Factor** | PBKDF2-HMAC-SHA256 (CLI: 600,000 iter; Web: 100,000 iter) | Low iteration counts vulnerable to offline GPU dictionary search if weak passphrases are used. | Enforced |
| **Zero-Disk Ingestion** | Child process environment table injection (`execve`/`subprocess.Popen(env=...)`) | Process memory inspection (`/proc/$PID/environ`) by same UID or elevated root; child processes leaking via crash dumps. | Documented & Bound |
| **Browser Secret Insulation** | Ephemeral RAM state, Web Crypto Subtle API | Uncontrolled clipboard access or malicious browser extensions reading input DOM fields prior to encryption. | Guarded |

---

## 🔍 Hidden Assumptions & Brittle Trust Loops

1. **Local UID Exposure (`/proc/<pid>/environ`)**:
   - Decrypted environment variables injected into child processes reside in the child process memory space and are readable on Linux systems by any process running under the same UID via `/proc/<pid>/environ`.
   - *Mitigation*: Run target workloads in rootless containers, set `PR_SET_DUMPABLE` where feasible, and limit ambient multi-tenant access on shared hosts.

2. **Passphrase Entropy & Keyring Reliance**:
   - The security of an offline encrypted vault strictly equals the entropy of the master passphrase or the host system keyring (`libsecret`/Keychain/Credential Manager).
   - *Mitigation*: Enforce minimum passphrase entropy checks and provide hardware token/PKI key wrapping integration paths.

3. **In-Browser DOM Residue**:
   - In single-page web environments, unencrypted strings held in form state or reactive closures are subject to heap retention until garbage collected.
   - *Mitigation*: Zero out sensitive ArrayBuffers immediately following encryption or serialization operations.

4. **Ambient Environment Poisoning & Precedence Drift**:
   - Unverified parent shell variables can shadow or override decrypted vault variables if injection precedence is not explicitly strictly defined.
   - *Mitigation*: Strict isolated environment sandboxing (`env -i` style clean slate injection) and explicit verification of target variable signatures before execution.

5. **Subprocess Pipe & Crash Dump Exposure**:
   - Child process panics or core dumps can write plaintext environment blocks to disk in world-readable crash directories.
   - *Mitigation*: Disable core dumps (`ulimit -c 0` / `prctl(PR_SET_DUMPABLE, 0)`) around sensitive command dispatch.

---

## 🛡️ Verification & Hardening Checklist

- [x] Symmetric AEAD authentication on all serialized secret envelopes.
- [x] Standardized PBKDF2 iteration bounds across runtime targets.
- [ ] Automated entropy linting for injected configuration payloads.
- [ ] Ephemeral memory zeroization across high-frequency CLI workflows.
