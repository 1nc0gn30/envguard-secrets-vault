#!/usr/bin/env python3
"""
EnvGuard Secrets Vault - Sovereign Standalone REST API & Web Workstation Server
Listens on http://127.0.0.1:8088 by default.
"""

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"
PUBLIC_DIR = ROOT_DIR / "public"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from envguard_secrets_vault.ui_server import start_server

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8088))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"⚡ Starting EnvGuard Secrets Vault on http://{host}:{port} ...")
    start_server(host=host, port=port, public_dir=str(PUBLIC_DIR))
