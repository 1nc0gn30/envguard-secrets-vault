"""Comprehensive unit tests for EncryptedVault and Cryptography Engine (vault.py)."""

import base64
import json
from pathlib import Path

import pytest

from envguard_secrets_vault.vault import (
    ARMOR_FOOTER,
    ARMOR_HEADER,
    AuthenticationError,
    EncryptedVault,
    InvalidPayloadError,
)


class TestVaultEncryptionDecryption:
    @pytest.fixture
    def vault(self):
        # Using 5,000 iterations for fast unit test execution while verifying logic
        return EncryptedVault(iterations=5_000)

    def test_roundtrip_basic_env(self, vault: EncryptedVault):
        sample_env = (
            "OPENAI_API_KEY=sk-proj-supersecretkey1234567890\n"
            "DATABASE_URL=postgresql://user:pass@localhost:5432/production\n"
            "PORT=8080\n"
        )
        password = "CorrectHorseBatteryStaple#2026!"
        
        armored = vault.encrypt_env(sample_env, password)
        assert ARMOR_HEADER in armored
        assert ARMOR_FOOTER in armored

        decrypted = vault.decrypt_env(armored, password)
        assert decrypted == sample_env

    def test_roundtrip_unicode_and_emojis(self, vault: EncryptedVault):
        complex_text = "APP_NAME=EnvGuard 🛡️\nWELCOME_MSG=Bonjour le monde! 🌍✨\nCJK_KEY=秘密鍵\n"
        password = "Pä$$wörd_🔑_2026"
        
        armored = vault.encrypt_env(complex_text, password)
        decrypted = vault.decrypt_env(armored, password)
        assert decrypted == complex_text

    def test_roundtrip_empty_string(self, vault: EncryptedVault):
        armored = vault.encrypt_env("", "pass123")
        decrypted = vault.decrypt_env(armored, "pass123")
        assert decrypted == ""

    def test_empty_password_raises_value_error(self, vault: EncryptedVault):
        with pytest.raises(ValueError):
            vault.encrypt_env("KEY=VAL", "")
        with pytest.raises(ValueError):
            vault.decrypt_env("some_payload", "")

    def test_low_iterations_guard(self):
        with pytest.raises(ValueError):
            EncryptedVault(iterations=500)

    def test_randomized_nonces_and_salts(self, vault: EncryptedVault):
        plain = "SECRET=identical_value"
        passw = "my_password"
        
        armored1 = vault.encrypt_env(plain, passw)
        armored2 = vault.encrypt_env(plain, passw)
        
        # Must produce different armored outputs due to random salt & nonce
        assert armored1 != armored2


class TestVaultAuthenticationAndTamperResistance:
    @pytest.fixture
    def vault(self):
        return EncryptedVault(iterations=5_000)

    def test_wrong_password_raises_authentication_error(self, vault: EncryptedVault):
        armored = vault.encrypt_env("SECRET=val", "correct_pass")
        with pytest.raises(AuthenticationError):
            vault.decrypt_env(armored, "wrong_pass")

    def test_tampered_ciphertext_raises_authentication_error(self, vault: EncryptedVault):
        armored = vault.encrypt_env("SECRET=val", "my_pass")
        
        # Decode and tamper ciphertext
        lines = [line.strip() for line in armored.splitlines() if line and not line.startswith("-----")]
        raw_b64 = "".join(lines)
        payload = json.loads(base64.b64decode(raw_b64).decode("utf-8"))
        
        ct = bytearray(base64.b64decode(payload["ciphertext"]))
        if ct:
            ct[0] ^= 0xFF  # Flip bits
        else:
            ct.append(0x01)
        payload["ciphertext"] = base64.b64encode(bytes(ct)).decode("ascii")

        # Re-envelope
        tampered_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        tampered_armored = f"{ARMOR_HEADER}\n{tampered_b64}\n{ARMOR_FOOTER}\n"

        with pytest.raises(AuthenticationError):
            vault.decrypt_env(tampered_armored, "my_pass")

    def test_tampered_tag_raises_authentication_error(self, vault: EncryptedVault):
        armored = vault.encrypt_env("SECRET=val", "my_pass")
        
        lines = [line.strip() for line in armored.splitlines() if line and not line.startswith("-----")]
        raw_b64 = "".join(lines)
        payload = json.loads(base64.b64decode(raw_b64).decode("utf-8"))
        
        tag = bytearray(base64.b64decode(payload["tag"]))
        tag[0] ^= 0x01
        payload["tag"] = base64.b64encode(bytes(tag)).decode("ascii")

        tampered_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        tampered_armored = f"{ARMOR_HEADER}\n{tampered_b64}\n{ARMOR_FOOTER}\n"

        with pytest.raises(AuthenticationError):
            vault.decrypt_env(tampered_armored, "my_pass")

    def test_invalid_envelope_raises_invalid_payload_error(self, vault: EncryptedVault):
        with pytest.raises(InvalidPayloadError):
            vault.decrypt_env("random garbage that is not base64 json", "pass")

        # Invalid version
        bad_version_obj = {
            "v": 999,
            "salt": "AAAA",
            "nonce": "BBBB",
            "tag": "CCCC",
            "ciphertext": "DDDD",
            "iter": 1000,
        }
        bad_b64 = base64.b64encode(json.dumps(bad_version_obj).encode("utf-8")).decode("ascii")
        with pytest.raises(InvalidPayloadError):
            vault.decrypt_env(f"{ARMOR_HEADER}\n{bad_b64}\n{ARMOR_FOOTER}", "pass")


class TestVaultFileOperations:
    def test_encrypt_and_decrypt_file(self, tmp_path: Path):
        vault = EncryptedVault(iterations=5_000)
        
        src_file = tmp_path / ".env"
        enc_file = tmp_path / ".env.vault"
        dec_file = tmp_path / ".env.decrypted"

        original_content = "API_KEY=sk-proj-filetest123456\nPORT=3000\n"
        src_file.write_text(original_content, encoding="utf-8")

        vault.encrypt_file(src_file, enc_file, "file_password_123")
        assert enc_file.is_file()
        assert ARMOR_HEADER in enc_file.read_text(encoding="utf-8")

        # Decrypt to file
        decrypted = vault.decrypt_file(enc_file, dec_file, "file_password_123")
        assert decrypted == original_content
        assert dec_file.read_text(encoding="utf-8") == original_content

        # Decrypt without writing to dest file
        decrypted_only = vault.decrypt_file(enc_file, None, "file_password_123")
        assert decrypted_only == original_content

    def test_large_payload_roundtrip(self):
        vault = EncryptedVault(iterations=5_000)
        # Create 50KB payload
        lines = [f"KEY_{i}={'a' * 50}_{i}" for i in range(1000)]
        large_env = "\n".join(lines) + "\n"
        
        armored = vault.encrypt_env(large_env, "strong_password_2026")
        decrypted = vault.decrypt_env(armored, "strong_password_2026")
        assert decrypted == large_env

    def test_tampered_iterations_raises_authentication_error(self):
        vault = EncryptedVault(iterations=5_000)
        armored = vault.encrypt_env("SECRET=val", "my_pass")
        
        lines = [line.strip() for line in armored.splitlines() if line and not line.startswith("-----")]
        raw_b64 = "".join(lines)
        payload = json.loads(base64.b64decode(raw_b64).decode("utf-8"))
        
        # Tamper iteration count
        payload["iter"] = 10000
        tampered_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        tampered_armored = f"{ARMOR_HEADER}\n{tampered_b64}\n{ARMOR_FOOTER}\n"

        with pytest.raises(AuthenticationError):
            vault.decrypt_env(tampered_armored, "my_pass")
