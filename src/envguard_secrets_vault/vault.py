"""Cryptographic Vault and Authenticated Encryption Engine for EnvGuard.

Provides PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations,
HMAC-SHA256-CTR authenticated stream cipher encryption, tamper verification,
and armored ASCII envelope export/import.
Zero external runtime dependencies - pure Python stdlib.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
from pathlib import Path
from typing import Any, Dict, Optional, Union

from envguard_secrets_vault.compat import atomic_write_text, safe_read_text

ARMOR_HEADER = "-----BEGIN ENVGUARD VAULT v1-----"
ARMOR_FOOTER = "-----END ENVGUARD VAULT v1-----"
DEFAULT_PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 16
NONCE_SIZE = 16


class VaultError(Exception):
    """Base exception for cryptographic vault operations."""


class AuthenticationError(VaultError):
    """Raised when decryption fails due to an incorrect password or tampered payload."""


class InvalidPayloadError(VaultError):
    """Raised when the armored payload structure is invalid or corrupt."""


class EncryptedVault:
    """Zero-dependency authenticated cryptographic vault for environment secrets."""

    def __init__(self, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> None:
        if iterations < 1000:
            raise ValueError("PBKDF2 iterations must be at least 1,000 for security.")
        self.iterations = iterations

    def _derive_keys(self, password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
        """Derive 64 bytes of key material using PBKDF2-HMAC-SHA256.

        Returns: (encryption_key: 32 bytes, mac_key: 32 bytes)
        """
        if not password:
            raise ValueError("Password cannot be empty.")
        derived = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode("utf-8"),
            salt=salt,
            iterations=iterations,
            dklen=64,
        )
        return derived[:32], derived[32:64]

    def _generate_keystream(self, key: bytes, nonce: bytes, length: int) -> bytes:
        """Generate keystream of specified length using HMAC-SHA256 in Counter (CTR) mode."""
        if length == 0:
            return b""
        num_blocks = math.ceil(length / 32)
        stream_chunks = []
        for i in range(num_blocks):
            counter_bytes = i.to_bytes(8, byteorder="big")
            block = hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
            stream_chunks.append(block)
        return b"".join(stream_chunks)[:length]

    def _xor_cipher(self, data: bytes, keystream: bytes) -> bytes:
        """XOR input bytes with keystream bytes."""
        return bytes(a ^ b for a, b in zip(data, keystream))

    def encrypt_env(self, content: str, password: str) -> str:
        """Encrypt environment text with password into an armored envelope string."""
        if not password:
            raise ValueError("Password cannot be empty.")

        plaintext_bytes = content.encode("utf-8")
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)

        enc_key, mac_key = self._derive_keys(password, salt, self.iterations)
        keystream = self._generate_keystream(enc_key, nonce, len(plaintext_bytes))
        ciphertext = self._xor_cipher(plaintext_bytes, keystream)

        # Authenticate with HMAC-SHA256 (Encrypt-then-MAC)
        # Authenticate Header + Iterations + Salt + Nonce + Ciphertext
        aad = b"ENVGUARD_VAULT_V1" + self.iterations.to_bytes(4, byteorder="big") + salt + nonce
        auth_tag = hmac.new(mac_key, aad + ciphertext, hashlib.sha256).digest()

        payload_obj: Dict[str, Any] = {
            "v": 1,
            "kdf": "PBKDF2-HMAC-SHA256",
            "iter": self.iterations,
            "cipher": "HMAC-SHA256-CTR",
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "tag": base64.b64encode(auth_tag).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

        json_bytes = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
        raw_b64 = base64.b64encode(json_bytes).decode("ascii")

        # Format lines into 64-character chunks
        chunked = "\n".join(raw_b64[i : i + 64] for i in range(0, len(raw_b64), 64))
        return f"{ARMOR_HEADER}\n{chunked}\n{ARMOR_FOOTER}\n"

    def decrypt_env(self, armored_payload: str, password: str) -> str:
        """Decrypt an armored envelope string using password with strict HMAC verification."""
        if not password:
            raise ValueError("Password cannot be empty.")

        cleaned = armored_payload.strip()
        if ARMOR_HEADER in cleaned and ARMOR_FOOTER in cleaned:
            # Extract content between headers
            start = cleaned.find(ARMOR_HEADER) + len(ARMOR_HEADER)
            end = cleaned.find(ARMOR_FOOTER)
            body_b64 = cleaned[start:end].replace("\n", "").replace("\r", "").strip()
        else:
            # Check if payload is raw json or direct b64
            body_b64 = cleaned.replace("\n", "").replace("\r", "").strip()

        try:
            json_raw = base64.b64decode(body_b64.encode("ascii")).decode("utf-8")
            data = json.loads(json_raw)
        except Exception as exc:
            raise InvalidPayloadError(f"Invalid armored payload envelope: {exc}") from exc

        if not isinstance(data, dict) or data.get("v") != 1:
            raise InvalidPayloadError("Unsupported or corrupt vault payload version.")

        try:
            iterations = int(data["iter"])
            salt = base64.b64decode(data["salt"])
            nonce = base64.b64decode(data["nonce"])
            received_tag = base64.b64decode(data["tag"])
            ciphertext = base64.b64decode(data["ciphertext"])
        except (KeyError, ValueError, TypeError) as exc:
            raise InvalidPayloadError(f"Corrupt vault payload fields: {exc}") from exc

        # Derive keys and verify HMAC tag before attempting any decryption
        enc_key, mac_key = self._derive_keys(password, salt, iterations)
        aad = b"ENVGUARD_VAULT_V1" + iterations.to_bytes(4, byteorder="big") + salt + nonce
        expected_tag = hmac.new(mac_key, aad + ciphertext, hashlib.sha256).digest()

        # Constant-time comparison
        if not hmac.compare_digest(expected_tag, received_tag):
            raise AuthenticationError(
                "Authentication failed: invalid password or corrupted/tampered payload."
            )

        keystream = self._generate_keystream(enc_key, nonce, len(ciphertext))
        plaintext_bytes = self._xor_cipher(ciphertext, keystream)

        try:
            return plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AuthenticationError("Payload decrypted but contains invalid UTF-8.") from exc

    def encrypt_file(
        self,
        source_path: Union[str, Path],
        dest_path: Union[str, Path],
        password: str,
    ) -> None:
        """Read source file, encrypt contents, and write atomically to destination."""
        content = safe_read_text(source_path)
        armored = self.encrypt_env(content, password)
        atomic_write_text(dest_path, armored)

    def decrypt_file(
        self,
        source_path: Union[str, Path],
        dest_path: Optional[Union[str, Path]],
        password: str,
    ) -> str:
        """Read encrypted file, decrypt contents, and optionally write to destination."""
        armored = safe_read_text(source_path)
        decrypted = self.decrypt_env(armored, password)
        if dest_path:
            atomic_write_text(dest_path, decrypted)
        return decrypted
