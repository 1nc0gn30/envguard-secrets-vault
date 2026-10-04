<div align="center">

<svg width="72" height="72" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Sphinx with Sword of Discernment in violet">
  <!-- Violet Aura & Shield -->
  <circle cx="50" cy="50" r="46" stroke="#8b5cf6" stroke-width="2" fill="#180d2b" fill-opacity="0.9" />
  <circle cx="50" cy="50" r="41" stroke="#a78bfa" stroke-width="0.75" stroke-dasharray="3 3" opacity="0.6" />
  
  <!-- Sphinx Wings & Form -->
  <path d="M26 66 C24 50 32 38 42 36 C38 44 38 56 38 66 Z" fill="#7c3aed" fill-opacity="0.35" stroke="#a78bfa" stroke-width="1.2" />
  <path d="M74 66 C76 50 68 38 58 36 C62 44 62 56 62 66 Z" fill="#7c3aed" fill-opacity="0.35" stroke="#a78bfa" stroke-width="1.2" />
  
  <!-- Sphinx Head, Nemes & Profile -->
  <path d="M44 32 C44 26 56 26 56 32 C56 38 53 41 50 42 C47 41 44 38 44 32 Z" fill="#4c1d95" stroke="#c084fc" stroke-width="1.2" />
  <path d="M42 32 C39 36 39 42 41 45 C43 45 44 43 44 40 Z" fill="#6d28d9" stroke="#a78bfa" stroke-width="0.8" />
  <path d="M58 32 C61 36 61 42 59 45 C57 45 56 43 56 40 Z" fill="#6d28d9" stroke="#a78bfa" stroke-width="0.8" />
  <path d="M48 35 L52 35" stroke="#ede9fe" stroke-width="1" stroke-linecap="round" />
  
  <!-- Sphinx Paws / Base -->
  <path d="M30 68 C34 65 42 66 45 68 C42 70 34 70 30 68 Z" fill="#5b21b6" stroke="#a78bfa" stroke-width="1" />
  <path d="M70 68 C66 65 58 66 55 68 C58 70 66 70 70 68 Z" fill="#5b21b6" stroke="#a78bfa" stroke-width="1" />
  <path d="M36 71 L64 71" stroke="#8b5cf6" stroke-width="1.5" stroke-linecap="round" />

  <!-- Sword of Discernment (Vertical Axis of Truth) -->
  <path d="M50 14 L50 64" stroke="#c084fc" stroke-width="2" stroke-linecap="round" />
  <path d="M49 14 L50 9 L51 14 Z" fill="#f5f3ff" stroke="#c084fc" stroke-width="1" />
  <line x1="43" y1="23" x2="57" y2="23" stroke="#e9d5ff" stroke-width="2" stroke-linecap="round" />
  <circle cx="50" cy="65" r="2" fill="#ede9fe" />
  
  <!-- Radial Sparks of Discernment -->
  <line x1="50" y1="6" x2="50" y2="3" stroke="#a78bfa" stroke-width="1.5" stroke-linecap="round" />
  <line x1="44" y1="8" x2="42" y2="6" stroke="#8b5cf6" stroke-width="1" stroke-linecap="round" />
  <line x1="56" y1="8" x2="58" y2="6" stroke="#8b5cf6" stroke-width="1" stroke-linecap="round" />
</svg>

### *The Sphinx of Discernment*
*Severing brittle assumptions; keeping silent what must remain unbroken.*

**The Sovereign Offer**: [EnvGuard Enterprise Lifetime Vault](https://buy.stripe.com/dR67vY1XpcOeeC4000) — **$19 Lifetime License** (Zero telemetry, perpetual offline airgap verification).

</div>

---

# EnvGuard Threat Model & Trust Assumptions Verification

This document makes explicit the implicit security assumptions, trust boundaries, and brittle loops across the EnvGuard Secrets Vault implementation.

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
- [x] Automated entropy linting for injected configuration payloads.
- [x] Ephemeral memory zeroization across high-frequency CLI workflows.

---

## ⚡ Antifragile Evolution: Turning Faults Into Armor

EnvGuard treats every secret pattern anomaly, failed decryption handshake, and environment fluctuation as training entropy rather than a pure terminal crash. Every unrecognized high-entropy token or structural drift is captured client-side into local quarantine heuristics—refining the vault's scanner signatures and immunizing subsequent workflows against ambient leakage without ever exfiltrating plaintexts.

