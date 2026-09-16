# Next.js Production Environment Security Audit Example

This example demonstrates how to use **EnvGuard Secrets Vault** to audit, sanitize, and secure environment configurations in a production Next.js application.

---

## 🚨 The Threat: Accidental Secrets & Client-Side Leaks

Next.js embeds any environment variable prefixed with `NEXT_PUBLIC_` directly into the client-side JavaScript bundle during build time. A common and catastrophic mistake occurs when developers mistakenly prefix sensitive backend credentials (such as payment secret keys, service tokens, or private database URIs) with `NEXT_PUBLIC_`:

```ini
# CRITICAL VULNERABILITY: This key is downloaded and readable by ANY visitor!
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51Oz9876543210abcdef...
```

EnvGuard flags both **known provider secret patterns** and **client-prefix leak anomalies** before code reaches version control or production builds.

---

## 🛠️ Step-by-Step Audit Workflow

### 1. Run Live Secret Audit
Scan `.env.production` against 50+ known provider signatures, Shannon entropy thresholds, and client bundle leak heuristics:

```bash
# Scan specific file
envguard scan examples/nextjs-env-audit/.env.production

# Or deep audit current directory
envguard audit examples/nextjs-env-audit/
```

**Sample Output:**
```text
🛡️  EnvGuard Secret Audit Report
File: examples/nextjs-env-audit/.env.production
Analyzed: 18 variables | Security Grade: F (0/100)

CRITICAL FINDINGS:
  [CRITICAL] NEXT_PUBLIC_STRIPE_SECRET_KEY
    -> Client Bundle Exposure: Secret key prefixed with NEXT_PUBLIC_ will be compiled into client JS!
    -> Pattern: Stripe Live Secret Key (sk_live_...)
  [CRITICAL] DATABASE_URL
    -> Embedded Credentials in PostgreSQL URI (postgres_admin:UltraSecret...)
  [CRITICAL] OPENAI_API_KEY
    -> Matches OpenAI Project Key format (sk-proj-...)
  [CRITICAL] ANTHROPIC_API_KEY
    -> Matches Anthropic Claude API Key format (sk-ant-api03-...)
  [CRITICAL] AWS_SECRET_ACCESS_KEY
    -> Matches AWS Secret Key format & high Shannon entropy (4.89 bits/char)
  [CRITICAL] GITHUB_PERSONAL_ACCESS_TOKEN
    -> Matches GitHub Personal Access Token format (ghp_...)

RECOMMENDATION:
  1. Revoke and rotate all detected production secrets immediately.
  2. Strip 'NEXT_PUBLIC_' prefix from backend-only secrets.
  3. Encrypt .env.production into an AES-256-GCM vault: `envguard vault create .env.production`
  4. Generate safe template: `envguard sanitize .env.production --output .env.example`
```

---

### 2. Generate Sanitized `.env.example` Template
Automatically strip all secrets and generate a clean, comment-preserved template suitable for committing to git:

```bash
envguard sanitize examples/nextjs-env-audit/.env.production --output examples/nextjs-env-audit/.env.example
```

---

### 3. Encrypt Production Secrets into a Portable Vault
Convert `.env.production` into an encrypted `secrets.vault` file using PBKDF2-HMAC-SHA256 and AES-256-GCM:

```bash
envguard vault create examples/nextjs-env-audit/.env.production \
  --output examples/nextjs-env-audit/secrets.vault \
  --password "Your-Secure-Master-Password-2026!"
```

---

### 4. Run Next.js with Zero-Disk Secret Injection
Launch Next.js in production without creating plaintext `.env.production` files on disk:

```bash
# Pass secrets in-memory directly to node/next process
envguard vault run --vault examples/nextjs-env-audit/secrets.vault -- npm run build
envguard vault run --vault examples/nextjs-env-audit/secrets.vault -- npm start
```

---

## 🔒 Security Checklist for Next.js

- [ ] Ensure `.env*.local` and `.env.production` are listed in `.gitignore`.
- [ ] Verify that no `NEXT_PUBLIC_` variables contain secrets, database URLs, or signing keys.
- [ ] Add the `env-security-gate.yml` workflow to `.github/workflows/` to block accidental PR commits.
- [ ] Use `envguard vault run` in container runtimes (Docker, Kubernetes, AWS ECS) to eliminate plaintext environment files in images.
