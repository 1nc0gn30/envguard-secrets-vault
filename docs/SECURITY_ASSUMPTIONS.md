<div align="center">

<svg width="76" height="76" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Skeleton in Dark Armor of Essential Structure in blue-green">
  <!-- Deep Blue-Green Abyss & Plate Aura -->
  <circle cx="50" cy="50" r="46" stroke="#0d9488" stroke-width="2" fill="#042f2e" fill-opacity="0.95" />
  <circle cx="50" cy="50" r="41" stroke="#14b8a6" stroke-width="0.75" stroke-dasharray="3 3" opacity="0.65" />

  <!-- Dark Armored Cuirass & Rib Structure -->
  <path d="M50 18 L62 26 L58 56 L50 64 L42 56 L38 26 Z" fill="#0f172a" stroke="#2dd4bf" stroke-width="1.8" />
  <line x1="50" y1="24" x2="50" y2="58" stroke="#0d9488" stroke-width="1.5" stroke-linecap="round" />
  <path d="M43 32 Q50 36 57 32" stroke="#2dd4bf" stroke-width="1.4" stroke-linecap="round" fill="none" />
  <path d="M41 40 Q50 44 59 40" stroke="#2dd4bf" stroke-width="1.4" stroke-linecap="round" fill="none" />
  <path d="M43 48 Q50 52 57 48" stroke="#14b8a6" stroke-width="1.4" stroke-linecap="round" fill="none" />

  <!-- Bone & Steel Pauldrons -->
  <path d="M38 26 L26 34 L32 44 L40 36 Z" fill="#022c22" stroke="#14b8a6" stroke-width="1.4" />
  <path d="M62 26 L74 34 L68 44 L60 36 Z" fill="#022c22" stroke="#14b8a6" stroke-width="1.4" />

  <!-- Skeletal Visor & Spinal Keystone -->
  <circle cx="46" cy="23" r="1.5" fill="#5eead4" />
  <circle cx="54" cy="23" r="1.5" fill="#5eead4" />
  <path d="M47 70 L53 70 L50 78 Z" fill="#0f766e" stroke="#2dd4bf" stroke-width="1" />
  <circle cx="50" cy="67" r="2.5" fill="#5eead4" />
</svg>
&nbsp;&nbsp;&nbsp;&nbsp;
<svg width="76" height="76" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="Inverted Pentagram of Misdirected Will in blue-violet">
  <!-- Blue-Violet Outer Boundary & Concentric Ring -->
  <circle cx="50" cy="50" r="46" stroke="#4f46e5" stroke-width="2" fill="#0f0c29" fill-opacity="0.95" />
  <circle cx="50" cy="50" r="41" stroke="#8b5cf6" stroke-width="0.75" stroke-dasharray="2 2" opacity="0.75" />

  <!-- Inverted Pentagram Geometry (Downward Apex) -->
  <!-- Vertices: Bottom (50, 86), Top-Left (16, 38), Top-Right (84, 38), Bottom-Left (29, 78), Bottom-Right (71, 78) - Inverted standard points: 
       Point 1 (Apex down): (50, 88)
       Point 2 (Top Right): (86, 38)
       Point 3 (Mid Left): (22, 60)
       Point 4 (Mid Right): (78, 60)
       Point 5 (Top Left): (14, 38)
  -->
  <polygon points="50,88 28,21 85,62 15,62 72,21" stroke="#a78bfa" stroke-width="2" stroke-linejoin="round" fill="#312e81" fill-opacity="0.35" />
  <circle cx="50" cy="88" r="2.5" fill="#c084fc" />
  <circle cx="28" cy="21" r="2.5" fill="#c084fc" />
  <circle cx="72" cy="21" r="2.5" fill="#c084fc" />
  <circle cx="15" cy="62" r="2.5" fill="#c084fc" />
  <circle cx="85" cy="62" r="2.5" fill="#c084fc" />
  <circle cx="50" cy="53" r="5" stroke="#818cf8" stroke-width="1.2" fill="#1e1b4b" />
</svg>

### *Skeleton in Dark Armor & Inverted Pentagram of Misdirected Will*
*Essential skeletal structure in blue-green tempered steel standing vigil against the inverted pull of misdirected will in blue-violet.*

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

6. **Misdirected Will & Implicit Ambient Trust (The Inverted Pentagram Loop)**:
   - Assuming that simply wrapping an environment variable in encryption cures downstream misuse is a failure of intention: unverified runtime consumers, blind trust in downstream library telemetry, or implicit export to sub-shells inverts the vault's protection into false security.
   - *Mitigation*: Enforce explicit egress assertions, strict allowlists for child process environment keys, and reject uninspected parent inheritance.

---

## 🛡️ Verification & Hardening Checklist

- [x] Symmetric AEAD authentication on all serialized secret envelopes.
- [x] Standardized PBKDF2 iteration bounds across runtime targets.
- [x] Automated entropy linting for injected configuration payloads.
- [x] Ephemeral memory zeroization across high-frequency CLI workflows.

---

## ⚡ Antifragile Evolution: Turning Faults Into Armor

EnvGuard treats every secret pattern anomaly, failed decryption handshake, and environment fluctuation as training entropy rather than a pure terminal crash. Every unrecognized high-entropy token or structural drift is captured client-side into local quarantine heuristics—refining the vault's scanner signatures and immunizing subsequent workflows against ambient leakage without ever exfiltrating plaintexts.

