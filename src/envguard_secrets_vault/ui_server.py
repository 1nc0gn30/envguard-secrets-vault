"""EnvGuard Secrets Vault - Google Material 3 Secrets Studio UI Server & REST API.

Zero-dependency HTTP server delivering the Google Material 3 Secrets Studio,
REST APIs for live secret auditing, masking, example generation, AES-256 vault
encryption/decryption, environment diffing, MCP client configurations,
and 1-click hardened ZIP bundle exporting.
"""

from __future__ import annotations

import base64
import datetime
import io
import json
import os
import sys
import urllib.parse
import zipfile
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from envguard_secrets_vault.mcp_server import (
    SERVER_NAME,
    SERVER_VERSION,
    diff_environments,
    generate_env_example,
    generate_mcp_client_config,
    get_diagnostics,
    mask_env_content,
    scan_file_or_dir,
    scan_secrets,
    vault_decrypt,
    vault_encrypt,
)

# Built-in Material 3 Studio SPA HTML
BUILTIN_STUDIO_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EnvGuard Secrets Vault — Studio</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: { 500: '#6366f1', 600: '#4f46e5', 700: '#4338ca' },
            surface: { 800: '#1e293b', 900: '#0f172a', 950: '#020617' }
          },
          fontFamily: {
            sans: ['"Plus Jakarta Sans"', 'sans-serif'],
            mono: ['"JetBrains Mono"', 'monospace']
          }
        }
      }
    }
  </script>
</head>
<body class="bg-surface-950 text-slate-100 min-h-screen font-sans antialiased flex flex-col">
  <!-- Top Navigation Bar -->
  <header class="border-b border-slate-800 bg-surface-900/80 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-500 to-purple-500 flex items-center justify-center shadow-lg shadow-indigo-500/30">
          <span class="text-xl">🛡️</span>
        </div>
        <div>
          <div class="flex items-center space-x-2">
            <h1 class="font-bold text-lg text-white">EnvGuard</h1>
            <span class="px-2 py-0.5 text-xs font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 rounded-full">v1.0.0</span>
          </div>
          <p class="text-xs text-slate-400">Zero-Trust Secrets Vault & Security Studio</p>
        </div>
      </div>
      <div class="flex items-center space-x-3">
        <button onclick="exportHardenedZip()" class="inline-flex items-center px-3.5 py-1.5 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg shadow-sm transition">
          <svg class="w-4 h-4 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
          Export Hardened ZIP
        </button>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
    <!-- Tabs Nav -->
    <div class="flex space-x-2 border-b border-slate-800 mb-6 overflow-x-auto pb-2">
      <button onclick="switchTab('scan')" id="tab-btn-scan" class="tab-btn active px-4 py-2 text-sm font-medium rounded-lg text-indigo-400 bg-slate-800 border border-indigo-500/30">🔍 Audit & Scan</button>
      <button onclick="switchTab('mask')" id="tab-btn-mask" class="tab-btn px-4 py-2 text-sm font-medium rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60">🎭 Mask Credentials</button>
      <button onclick="switchTab('example')" id="tab-btn-example" class="tab-btn px-4 py-2 text-sm font-medium rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60">📄 .env.example</button>
      <button onclick="switchTab('vault')" id="tab-btn-vault" class="tab-btn px-4 py-2 text-sm font-medium rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60">🔐 Armored Vault</button>
      <button onclick="switchTab('diff')" id="tab-btn-diff" class="tab-btn px-4 py-2 text-sm font-medium rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60">⚖️ Environment Diff</button>
      <button onclick="switchTab('mcp')" id="tab-btn-mcp" class="tab-btn px-4 py-2 text-sm font-medium rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60">🔌 MCP Integration</button>
    </div>

    <!-- TAB: SCAN & AUDIT -->
    <section id="tab-scan" class="tab-content block">
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div class="lg:col-span-6 flex flex-col">
          <div class="bg-surface-900 border border-slate-800 rounded-xl p-5 flex flex-col flex-1 shadow-sm">
            <div class="flex items-center justify-between mb-3">
              <label class="text-sm font-semibold text-slate-200">Raw .env Configuration</label>
              <button onclick="loadSampleEnv()" class="text-xs text-indigo-400 hover:text-indigo-300">Load Leaked Sample</button>
            </div>
            <textarea id="scan-input" class="w-full flex-1 min-h-[300px] bg-surface-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 focus:ring-2 focus:ring-indigo-500 focus:outline-none" placeholder="PORT=8080&#10;OPENAI_API_KEY=sk-proj-9876543210abcdef...&#10;DATABASE_URL=postgres://user:secret@localhost:5432/app"></textarea>
            <div class="mt-4 flex items-center justify-between">
              <span class="text-xs text-slate-400">Zero external dependencies. Evaluated locally.</span>
              <button onclick="runAudit()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium rounded-lg transition shadow">Run Security Audit</button>
            </div>
          </div>
        </div>

        <div class="lg:col-span-6 flex flex-col">
          <div id="scan-results-box" class="bg-surface-900 border border-slate-800 rounded-xl p-5 flex flex-col flex-1 shadow-sm">
            <div class="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
              <div>
                <h3 class="font-bold text-slate-100">Security Posture</h3>
                <p class="text-xs text-slate-400">Automated 20+ Pattern & Entropy Scan</p>
              </div>
              <div id="score-badge" class="px-4 py-2 rounded-xl text-lg font-bold bg-slate-800 text-slate-300">-- / 100</div>
            </div>
            <div id="findings-container" class="flex-1 overflow-y-auto space-y-3 max-h-[350px]">
              <div class="text-center py-12 text-slate-500 text-sm">Click "Run Security Audit" to inspect secrets.</div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- TAB: MASK -->
    <section id="tab-mask" class="tab-content hidden">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="bg-surface-900 border border-slate-800 rounded-xl p-5">
          <label class="text-sm font-semibold text-slate-200 block mb-2">Input .env to Mask</label>
          <textarea id="mask-input" class="w-full h-80 bg-surface-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 focus:outline-none" placeholder="Paste sensitive .env..."></textarea>
          <div class="mt-4 flex items-center justify-between">
            <select id="mask-mode" class="bg-surface-950 border border-slate-800 text-xs rounded-lg px-3 py-2 text-slate-300">
              <option value="partial">Partial Mask (AKIA****9A8B)</option>
              <option value="full">Full Mask (****************)</option>
            </select>
            <button onclick="runMask()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium rounded-lg">Mask Sensitive Variables</button>
          </div>
        </div>
        <div class="bg-surface-900 border border-slate-800 rounded-xl p-5">
          <div class="flex items-center justify-between mb-2">
            <label class="text-sm font-semibold text-slate-200">Masked Output</label>
            <button onclick="copyToClipboard('mask-output')" class="text-xs text-indigo-400 hover:underline">Copy</button>
          </div>
          <textarea id="mask-output" readonly class="w-full h-80 bg-surface-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-emerald-400 focus:outline-none"></textarea>
        </div>
      </div>
    </section>

    <!-- TAB: EXAMPLE -->
    <section id="tab-example" class="tab-content hidden">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div class="bg-surface-900 border border-slate-800 rounded-xl p-5">
          <label class="text-sm font-semibold text-slate-200 block mb-2">Live .env Configuration</label>
          <textarea id="example-input" class="w-full h-80 bg-surface-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 focus:outline-none" placeholder="Paste .env to sanitize..."></textarea>
          <div class="mt-4 flex justify-end">
            <button onclick="runGenerateExample()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium rounded-lg">Generate .env.example</button>
          </div>
        </div>
        <div class="bg-surface-900 border border-slate-800 rounded-xl p-5">
          <div class="flex items-center justify-between mb-2">
            <label class="text-sm font-semibold text-slate-200">Sanitized .env.example Template</label>
            <button onclick="copyToClipboard('example-output')" class="text-xs text-indigo-400 hover:underline">Copy</button>
          </div>
          <textarea id="example-output" readonly class="w-full h-80 bg-surface-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-indigo-300 focus:outline-none"></textarea>
        </div>
      </div>
    </section>

    <!-- TAB: VAULT -->
    <section id="tab-vault" class="tab-content hidden">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Encrypt -->
        <div class="bg-surface-900 border border-slate-800 rounded-xl p-5">
          <h3 class="text-sm font-bold text-white mb-2">🔒 Encrypt .env to Armored Vault</h3>
          <p class="text-xs text-slate-400 mb-3">PBKDF2-HMAC-SHA256 (100k iters) + AES-256-CTR + HMAC-SHA256</p>
          <textarea id="vault-plain" class="w-full h-48 bg-surface-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 focus:outline-none mb-3" placeholder="Plaintext .env content..."></textarea>
          <div class="flex space-x-2 mb-3">
            <input type="password" id="encrypt-pwd" class="flex-1 bg-surface-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200" placeholder="Master encryption password">
            <button onclick="runEncrypt()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-medium rounded-lg">Encrypt</button>
          </div>
          <textarea id="vault-encrypted-out" readonly class="w-full h-40 bg-surface-950 border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-amber-300 focus:outline-none" placeholder="Encrypted armored vault will appear here..."></textarea>
        </div>

        <!-- Decrypt -->
        <div class="bg-surface-900 border border-slate-800 rounded-xl p-5">
          <h3 class="text-sm font-bold text-white mb-2">🔓 Decrypt Armored Vault</h3>
          <p class="text-xs text-slate-400 mb-3">Restore plaintext with master password verification</p>
          <textarea id="vault-armor-in" class="w-full h-48 bg-surface-950 border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-amber-300 focus:outline-none mb-3" placeholder="Paste -----BEGIN ENVGUARD ENCRYPTED VAULT----- payload..."></textarea>
          <div class="flex space-x-2 mb-3">
            <input type="password" id="decrypt-pwd" class="flex-1 bg-surface-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200" placeholder="Master decryption password">
            <button onclick="runDecrypt()" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium rounded-lg">Decrypt</button>
          </div>
          <textarea id="vault-decrypted-out" readonly class="w-full h-40 bg-surface-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-emerald-400 focus:outline-none" placeholder="Decrypted plaintext .env will appear here..."></textarea>
        </div>
      </div>
    </section>

    <!-- TAB: DIFF -->
    <section id="tab-diff" class="tab-content hidden">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <div>
          <label class="text-xs font-semibold text-slate-300 block mb-1">Environment A (.env.development)</label>
          <textarea id="diff-env-a" class="w-full h-48 bg-surface-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 focus:outline-none" placeholder="PORT=3000&#10;DEBUG=true&#10;API_KEY=dev-123"></textarea>
        </div>
        <div>
          <label class="text-xs font-semibold text-slate-300 block mb-1">Environment B (.env.production)</label>
          <textarea id="diff-env-b" class="w-full h-48 bg-surface-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 focus:outline-none" placeholder="PORT=8080&#10;DEBUG=false&#10;REDIS_URL=redis://prod:6379"></textarea>
        </div>
      </div>
      <div class="flex justify-end mb-4">
        <button onclick="runDiff()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium rounded-lg">Compare Environments</button>
      </div>
      <div id="diff-results" class="bg-surface-900 border border-slate-800 rounded-xl p-5">
        <p class="text-xs text-slate-500 text-center py-6">Enter Environment A & B contents above and click Compare.</p>
      </div>
    </section>

    <!-- TAB: MCP -->
    <section id="tab-mcp" class="tab-content hidden">
      <div class="bg-surface-900 border border-slate-800 rounded-xl p-6">
        <h3 class="font-bold text-white text-base mb-2">Model Context Protocol (MCP) Server Setup</h3>
        <p class="text-xs text-slate-400 mb-6">Connect EnvGuard directly to Claude Desktop, Cursor, Cline, or Zed AI agents.</p>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label class="text-xs font-semibold text-slate-300 block mb-2">Claude Desktop Config (claude_desktop_config.json)</label>
            <pre id="mcp-claude" class="bg-surface-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-indigo-300 overflow-x-auto"></pre>
          </div>
          <div>
            <label class="text-xs font-semibold text-slate-300 block mb-2">Cursor Config (.cursor/mcp.json)</label>
            <pre id="mcp-cursor" class="bg-surface-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-emerald-300 overflow-x-auto"></pre>
          </div>
        </div>
      </div>
    </section>
  </main>

  <script>
    function switchTab(tabId) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
      document.querySelectorAll('.tab-btn').forEach(el => {
        el.classList.remove('text-indigo-400', 'bg-slate-800', 'border', 'border-indigo-500/30');
        el.classList.add('text-slate-400');
      });
      document.getElementById('tab-' + tabId).classList.remove('hidden');
      const btn = document.getElementById('tab-btn-' + tabId);
      btn.classList.add('text-indigo-400', 'bg-slate-800', 'border', 'border-indigo-500/30');
      btn.classList.remove('text-slate-400');
      if (tabId === 'mcp') loadMcpConfigs();
    }

    function loadSampleEnv() {
      document.getElementById('scan-input').value = `PORT=8080\\nNODE_ENV=production\\nOPENAI_API_KEY=sk-proj-dummyOpenAiKey00000000000000000000\\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\\nDATABASE_URL=postgres://app_user:super_secret_password_123@prod-db.internal:5432/main\\nSTRIPE_SECRET_KEY=sk_mock_dummyStripeKey00000000000000000000\\nJWT_SECRET=super_hardcoded_jwt_secret_token_val_9999\\n`;
      document.getElementById('mask-input').value = document.getElementById('scan-input').value;
      document.getElementById('example-input').value = document.getElementById('scan-input').value;
      document.getElementById('vault-plain').value = document.getElementById('scan-input').value;
    }

    async function runAudit() {
      const content = document.getElementById('scan-input').value;
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ content })
      });
      const data = await res.json();
      const badge = document.getElementById('score-badge');
      badge.innerText = `${data.score} / 100 (${data.grade})`;
      badge.className = `px-4 py-2 rounded-xl text-lg font-bold ${data.score >= 80 ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`;

      const box = document.getElementById('findings-container');
      if (!data.findings || data.findings.length === 0) {
        box.innerHTML = '<div class="text-center py-10 text-emerald-400 font-medium">🎉 Zero leaks detected! 100% Secure.</div>';
        return;
      }
      box.innerHTML = data.findings.map(f => `
        <div class="p-3.5 bg-surface-950 border border-slate-800 rounded-lg">
          <div class="flex items-center justify-between mb-1">
            <span class="text-xs font-bold ${f.severity === 'CRITICAL' ? 'text-red-400' : 'text-amber-400'}">[${f.severity}] ${f.name}</span>
            <span class="text-xs text-slate-500">Line ${f.line} (-${f.deduction} pts)</span>
          </div>
          <p class="text-xs text-slate-400 mb-1.5">${f.description}</p>
          <div class="text-[11px] font-mono text-indigo-300 bg-slate-900/80 px-2 py-1 rounded">💡 ${f.remediation}</div>
        </div>
      `).join('');
    }

    async function runMask() {
      const content = document.getElementById('mask-input').value;
      const mode = document.getElementById('mask-mode').value;
      const res = await fetch('/api/mask', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ content, mode })
      });
      const data = await res.json();
      document.getElementById('mask-output').value = data.masked_content || '';
    }

    async function runGenerateExample() {
      const content = document.getElementById('example-input').value;
      const res = await fetch('/api/example', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ content })
      });
      const data = await res.json();
      document.getElementById('example-output').value = data.example_content || '';
    }

    async function runEncrypt() {
      const content = document.getElementById('vault-plain').value;
      const password = document.getElementById('encrypt-pwd').value;
      if (!password) { alert('Enter encryption password'); return; }
      const res = await fetch('/api/encrypt', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ content, password })
      });
      const data = await res.json();
      document.getElementById('vault-encrypted-out').value = data.vault_armor || data.error;
      document.getElementById('vault-armor-in').value = data.vault_armor || '';
      document.getElementById('decrypt-pwd').value = password;
    }

    async function runDecrypt() {
      const vault_armor = document.getElementById('vault-armor-in').value;
      const password = document.getElementById('decrypt-pwd').value;
      if (!password) { alert('Enter decryption password'); return; }
      const res = await fetch('/api/decrypt', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ vault_armor, password })
      });
      const data = await res.json();
      document.getElementById('vault-decrypted-out').value = data.decrypted_content || data.error;
    }

    async function runDiff() {
      const env_a = document.getElementById('diff-env-a').value;
      const env_b = document.getElementById('diff-env-b').value;
      const res = await fetch('/api/diff', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ env_a, env_b })
      });
      const data = await res.json();
      const diffBox = document.getElementById('diff-results');
      diffBox.innerHTML = `
        <div class="grid grid-cols-3 gap-2 mb-4 text-center">
          <div class="bg-surface-950 p-3 rounded-lg"><div class="text-xs text-slate-400">Total Keys A</div><div class="font-bold text-indigo-400">${data.total_keys_a}</div></div>
          <div class="bg-surface-950 p-3 rounded-lg"><div class="text-xs text-slate-400">Total Keys B</div><div class="font-bold text-indigo-400">${data.total_keys_b}</div></div>
          <div class="bg-surface-950 p-3 rounded-lg"><div class="text-xs text-slate-400">Identical</div><div class="font-bold text-emerald-400">${data.identical_values_count}</div></div>
        </div>
        <div class="space-y-2">
          ${data.differences.map(d => `
            <div class="p-2.5 bg-surface-950 border border-slate-800 rounded font-mono text-xs flex justify-between items-center">
              <div><span class="font-bold text-slate-200">${d.key}</span> <span class="text-slate-500">(${d.status})</span></div>
              <div class="text-slate-400">A: <span class="text-indigo-300">${d.val_a || 'MISSING'}</span> | B: <span class="text-amber-300">${d.val_b || 'MISSING'}</span></div>
            </div>
          `).join('')}
        </div>
      `;
    }

    async function loadMcpConfigs() {
      const res = await fetch('/api/mcp/config');
      const data = await res.json();
      document.getElementById('mcp-claude').innerText = JSON.stringify(data.claude_desktop, null, 2);
      document.getElementById('mcp-cursor').innerText = JSON.stringify(data.cursor, null, 2);
    }

    function exportHardenedZip() {
      const content = document.getElementById('scan-input').value || 'PORT=8080\\n';
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = '/api/export-zip';
      const input = document.createElement('input');
      input.type = 'hidden';
      input.name = 'content';
      input.value = content;
      form.appendChild(input);
      document.body.appendChild(form);
      form.submit();
      document.body.removeChild(form);
    }

    function copyToClipboard(elemId) {
      const val = document.getElementById(elemId).value;
      navigator.clipboard.writeText(val);
      alert('Copied to clipboard!');
    }
  </script>
</body>
</html>
"""


class StudioHTTPRequestHandler(SimpleHTTPRequestHandler):
    """HTTP Request handler serving Studio UI and REST APIs."""

    def __init__(self, *args: Any, directory: Optional[str] = None, **kwargs: Any) -> None:
        if directory is None:
            repo_public = Path(__file__).resolve().parent.parent.parent / "public"
            if repo_public.is_dir() and (repo_public / "index.html").is_file():
                directory = str(repo_public)
            else:
                directory = str(Path.cwd() / "public")
        self.public_dir = Path(directory)
        super().__init__(*args, directory=directory, **kwargs)

    def _send_json_response(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == "/api/health":
            self._send_json_response({
                "status": "ok",
                "app": SERVER_NAME,
                "version": SERVER_VERSION,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
            return

        if path == "/api/mcp/config":
            params = urllib.parse.parse_qs(parsed_url.query)
            client_type = params.get("client", ["all"])[0]
            configs = generate_mcp_client_config(client_type)
            self._send_json_response(configs)
            return

        if path == "/api/diagnostics":
            self._send_json_response(get_diagnostics())
            return

        # Serve static HTML or built-in UI fallback
        index_file = self.public_dir / "index.html"
        if path in ("/", "/index.html"):
            if index_file.exists():
                super().do_GET()
            else:
                html_bytes = BUILTIN_STUDIO_HTML.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_bytes)))
                self.end_headers()
                self.wfile.write(html_bytes)
            return

        super().do_GET()

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        # Handle form-encoded or JSON payload
        content_type = self.headers.get("Content-Type", "")
        data: Dict[str, Any] = {}
        if "application/json" in content_type:
            try:
                data = json.loads(post_data.decode("utf-8")) if post_data else {}
            except Exception:
                data = {}
        elif "application/x-www-form-urlencoded" in content_type:
            parsed_form = urllib.parse.parse_qs(post_data.decode("utf-8"))
            data = {k: v[0] for k, v in parsed_form.items()}

        if path == "/api/scan":
            raw_content = data.get("content", "")
            target_path = data.get("path")
            min_score = int(data.get("min_score", 80))
            if target_path:
                try:
                    res = scan_file_or_dir(target_path, min_score=min_score)
                    self._send_json_response(res)
                except Exception as e:
                    self._send_json_response({"error": str(e)}, status=400)
            else:
                res = scan_secrets(raw_content, source="<api_input>", min_score=min_score)
                self._send_json_response(res)
            return

        if path == "/api/mask":
            raw_content = data.get("content", "")
            mode = data.get("mode", "partial")
            res = mask_env_content(raw_content, mode=mode)
            self._send_json_response(res)
            return

        if path == "/api/example":
            raw_content = data.get("content", "")
            res = generate_env_example(raw_content)
            self._send_json_response(res)
            return

        if path == "/api/encrypt":
            raw_content = data.get("content", "")
            password = data.get("password", "")
            if not password:
                self._send_json_response({"error": "Password is required"}, status=400)
                return
            try:
                res = vault_encrypt(raw_content, password=password)
                self._send_json_response(res)
            except Exception as e:
                self._send_json_response({"error": str(e)}, status=400)
            return

        if path == "/api/decrypt":
            vault_armor = data.get("vault_armor", "") or data.get("vault", "")
            password = data.get("password", "")
            if not password:
                self._send_json_response({"error": "Password is required"}, status=400)
                return
            try:
                res = vault_decrypt(vault_armor, password=password)
                self._send_json_response(res)
            except Exception as e:
                self._send_json_response({"error": str(e)}, status=400)
            return

        if path == "/api/diff":
            env_a = data.get("env_a", "")
            env_b = data.get("env_b", "")
            name_a = data.get("name_a", "Environment A")
            name_b = data.get("name_b", "Environment B")
            res = diff_environments(env_a, env_b, name_a=name_a, name_b=name_b)
            self._send_json_response(res)
            return

        if path == "/api/mcp/config":
            client_type = data.get("client", "all")
            configs = generate_mcp_client_config(client_type)
            self._send_json_response(configs)
            return

        if path == "/api/export-zip":
            raw_content = data.get("content", "PORT=8080\n")
            zip_buffer = io.BytesIO()

            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                # 1. Sanitized .env.example
                example_res = generate_env_example(raw_content)
                zf.writestr(".env.example", example_res["example_content"])

                # 2. Masked .env.masked
                masked_res = mask_env_content(raw_content, mode="partial")
                zf.writestr(".env.masked", masked_res["masked_content"])

                # 3. Security Audit Report JSON
                audit_res = scan_secrets(raw_content, source=".env")
                zf.writestr("audit-report.json", json.dumps(audit_res, indent=2))

                # 4. MCP Configs
                mcp_configs = generate_mcp_client_config("all")
                zf.writestr("mcp-configs/claude_desktop.json", json.dumps(mcp_configs["claude_desktop"], indent=2))
                zf.writestr("mcp-configs/cursor_mcp.json", json.dumps(mcp_configs["cursor"], indent=2))
                zf.writestr("mcp-configs/cline_mcp.json", json.dumps(mcp_configs["cline"], indent=2))
                zf.writestr("mcp-configs/zed_settings.json", json.dumps(mcp_configs["zed"], indent=2))

                # 5. README instructions
                readme_text = (
                    "# EnvGuard Hardened Secrets Bundle\n\n"
                    "This archive was generated by EnvGuard Secrets Vault Studio.\n\n"
                    "## Contents:\n"
                    "- `.env.example`: Sanitized template safe for version control.\n"
                    "- `.env.masked`: Partially redacted environment snapshot.\n"
                    "- `audit-report.json`: Full security posture and finding logs.\n"
                    "- `mcp-configs/`: Ready-to-use Model Context Protocol server configurations.\n"
                )
                zf.writestr("README.md", readme_text)

            zip_bytes = zip_buffer.getvalue()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="envguard-hardened-bundle.zip"')
            self.send_header("Content-Length", str(len(zip_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(zip_bytes)
            return

        self._send_json_response({"error": f"Endpoint not found: {path}"}, status=404)


def create_server(host: str = "0.0.0.0", port: int = 8087, public_dir: Optional[str] = None) -> ThreadingHTTPServer:
    """Creates a ThreadingHTTPServer instance for EnvGuard Studio."""
    handler = lambda *args, **kwargs: StudioHTTPRequestHandler(*args, directory=public_dir, **kwargs)
    return ThreadingHTTPServer((host, port), handler)


def start_server(host: str = "0.0.0.0", port: int = 8087, public_dir: Optional[str] = None) -> None:
    """Starts the EnvGuard Secrets Studio HTTP Server."""
    server = create_server(host=host, port=port, public_dir=public_dir)
    print(f"[EnvGuard Studio] Server listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[EnvGuard Studio] Server stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    start_server()
