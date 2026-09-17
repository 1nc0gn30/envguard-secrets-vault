"""EnvGuard Secrets Vault.

Zero-dependency .env security auditor, armored AES-256 secrets vault,
diff analyzer, CI/CD security gate, and Model Context Protocol (MCP) server.
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "EnvGuard Secrets Vault Contributors"
__license__ = "MIT"

from envguard_secrets_vault.ci_gate import run_security_check
from envguard_secrets_vault.cli import main as cli_main
from envguard_secrets_vault.mcp_server import (
    MCP_PROTOCOL_VERSION,
    MCP_TOOLS_DEFINITIONS,
    SERVER_NAME,
    SERVER_VERSION,
    MCPServer,
    calculate_shannon_entropy,
    diff_environments,
    generate_env_example,
    generate_mcp_client_config,
    get_diagnostics,
    mask_env_content,
    run_mcp_server,
    scan_file_or_dir,
    scan_secrets,
    vault_decrypt,
    vault_encrypt,
)
from envguard_secrets_vault.ui_server import create_server, start_server
from envguard_secrets_vault.entropy_analyzer import (
    AlphabetType,
    EntropyProfile,
    CompiledCustomRule,
    detect_alphabet,
    analyze_entropy_profile,
    compile_custom_rules,
    scan_with_custom_rules,
)
from envguard_secrets_vault.shamir_quorum import (
    SecretShare,
    ShamirSecretSharing,
    split_secret_into_shares,
    combine_shares_to_secret,
)

__all__ = [
    "__version__",
    "SERVER_NAME",
    "SERVER_VERSION",
    "MCP_PROTOCOL_VERSION",
    "MCP_TOOLS_DEFINITIONS",
    "MCPServer",
    "run_mcp_server",
    "run_security_check",
    "scan_secrets",
    "scan_file_or_dir",
    "calculate_shannon_entropy",
    "mask_env_content",
    "generate_env_example",
    "vault_encrypt",
    "vault_decrypt",
    "diff_environments",
    "get_diagnostics",
    "generate_mcp_client_config",
    "create_server",
    "start_server",
    "cli_main",
    "AlphabetType",
    "EntropyProfile",
    "CompiledCustomRule",
    "detect_alphabet",
    "analyze_entropy_profile",
    "compile_custom_rules",
    "scan_with_custom_rules",
    "SecretShare",
    "ShamirSecretSharing",
    "split_secret_into_shares",
    "combine_shares_to_secret",
]
