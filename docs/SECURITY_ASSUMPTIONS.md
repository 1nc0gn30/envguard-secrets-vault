<div align="center">

<svg width="76" height="76" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Golden Scales of Exact Equilibrium in emerald">
  <!-- Emerald Aura & Halo -->
  <circle cx="50" cy="50" r="46" stroke="#10b981" stroke-width="2" fill="#042f2e" fill-opacity="0.92" />
  <circle cx="50" cy="50" r="41" stroke="#34d399" stroke-width="0.75" stroke-dasharray="3 3" opacity="0.6" />

  <!-- Fulcrum Pillar & Base (Gold & Emerald Accents) -->
  <path d="M40 76 L60 76 L56 70 L44 70 Z" fill="#d97706" stroke="#fbbf24" stroke-width="1.2" />
  <line x1="50" y1="70" x2="50" y2="28" stroke="#f59e0b" stroke-width="2.5" stroke-linecap="round" />
  <circle cx="50" cy="27" r="4" fill="#fbbf24" stroke="#d97706" stroke-width="1.2" />
  <circle cx="50" cy="27" r="1.5" fill="#10b981" />

  <!-- Horizontal Beam (Exact Equilibrium) -->
  <line x1="22" y1="33" x2="78" y2="33" stroke="#fbbf24" stroke-width="2" stroke-linecap="round" />
  <circle cx="22" cy="33" r="2" fill="#f59e0b" />
  <circle cx="78" cy="33" r="2" fill="#f59e0b" />

  <!-- Left Scale (Zero Exposure Security) -->
  <line x1="22" y1="33" x2="14" y2="52" stroke="#d97706" stroke-width="1" />
  <line x1="22" y1="33" x2="30" y2="52" stroke="#d97706" stroke-width="1" />
  <path d="M11 52 Q22 60 33 52 Z" fill="#b45309" stroke="#fbbf24" stroke-width="1.2" />
  <circle cx="22" cy="53" r="1.8" fill="#34d399" />

  <!-- Right Scale (Flawless Velocity & Usability) -->
  <line x1="78" y1="33" x2="70" y2="52" stroke="#d97706" stroke-width="1" />
  <line x1="78" y1="33" x2="86" y2="52" stroke="#d97706" stroke-width="1" />
  <path d="M67 52 Q78 60 89 52 Z" fill="#b45309" stroke="#fbbf24" stroke-width="1.2" />
  <circle cx="78" cy="53" r="1.8" fill="#34d399" />

  <!-- Emerald Rays of Equilibrium -->
  <circle cx="50" cy="18" r="1.5" fill="#34d399" />
  <line x1="50" y1="13" x2="50" y2="10" stroke="#10b981" stroke-width="1.5" stroke-linecap="round" />
  <line x1="44" y1="15" x2="42" y2="13" stroke="#10b981" stroke-width="1" stroke-linecap="round" />
  <line x1="56" y1="15" x2="58" y2="13" stroke="#10b981" stroke-width="1" stroke-linecap="round" />
</svg>

### *Golden Scales of Exact Equilibrium*
*Weighed in emerald balance: zero exposure, unbroken secrecy, flawless audit.*

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

