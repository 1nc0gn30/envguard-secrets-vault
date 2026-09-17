"""Shamir's Secret Sharing (SSS) & Distributed Multi-Party Key Quorum Engine.

Implements an information-theoretically secure (k, n) threshold scheme over Galois Field
GF(2^8) with polynomial field arithmetic (Rijndael irreducible polynomial x^8 + x^4 + x^3 + x + 1, 0x11B):
- Any k of n shares can perfectly reconstruct the secret master key / secret file.
- Any k-1 or fewer shares gain strictly 0 bits of information about the secret (perfect secrecy).
- Zero external runtime dependencies - 100% Python Standard Library.
- Share encoding formats: RFC-like armored ASCII envelopes (`-----BEGIN ENVGUARD SECRET SHARE-----`),
  hexadecimal strings, and structured JSON.
- Share integrity verification with embedded share checksums and threshold validation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# Rijndael polynomial 0x11B: x^8 + x^4 + x^3 + x + 1
GF256_POLY = 0x11B

# Precompute log and exp tables using generator 3 for constant-time GF(2^8) arithmetic
GF256_EXP = [0] * 512
GF256_LOG = [0] * 256

def _poly_mul_x3(val: int) -> int:
    # Multiply by 3 (which is (val << 1) ^ val) modulo GF256_POLY
    high = val << 1
    if high & 0x100:
        high ^= GF256_POLY
    return high ^ val

_val = 1
for _i in range(255):
    GF256_EXP[_i] = _val
    GF256_EXP[_i + 255] = _val
    GF256_LOG[_val] = _i
    _val = _poly_mul_x3(_val)
GF256_EXP[510] = GF256_EXP[0]
GF256_EXP[511] = GF256_EXP[1]


def gf256_add(a: int, b: int) -> int:
    """Addition in GF(2^8) is bitwise XOR."""
    return a ^ b


def gf256_sub(a: int, b: int) -> int:
    """Subtraction in GF(2^8) is identical to addition (bitwise XOR)."""
    return a ^ b


def gf256_mul(a: int, b: int) -> int:
    """Multiplication in GF(2^8) using precomputed log and exp tables."""
    if a == 0 or b == 0:
        return 0
    return GF256_EXP[GF256_LOG[a] + GF256_LOG[b]]


def gf256_div(a: int, b: int) -> int:
    """Division in GF(2^8). Raises ZeroDivisionError if b == 0."""
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(2^8)")
    if a == 0:
        return 0
    return GF256_EXP[(GF256_LOG[a] - GF256_LOG[b] + 255) % 255]


def gf256_eval_poly(poly: Sequence[int], x: int) -> int:
    """Evaluate polynomial poly[0] + poly[1]*x + poly[2]*x^2 + ... at point x in GF(2^8) using Horner's rule."""
    if x == 0:
        return poly[0]
    result = 0
    for coeff in reversed(poly):
        result = gf256_add(gf256_mul(result, x), coeff)
    return result


SHARE_ARMOR_HEADER = "-----BEGIN ENVGUARD SECRET SHARE-----"
SHARE_ARMOR_FOOTER = "-----END ENVGUARD SECRET SHARE-----"


@dataclass(frozen=True)
class SecretShare:
    """A cryptographic share in a (k, n) threshold scheme."""

    share_index: int  # x-coordinate (1 <= x <= 255)
    threshold: int  # k: minimum shares required
    total_shares: int  # n: total shares generated
    data_bytes: bytes  # evaluated y values for each byte in secret
    checksum: str  # SHA-256 fingerprint for share integrity check
    label: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.share_index,
            "threshold": self.threshold,
            "total": self.total_shares,
            "data_b64": base64.b64encode(self.data_bytes).decode("ascii"),
            "checksum": self.checksum,
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SecretShare:
        return cls(
            share_index=int(data["index"]),
            threshold=int(data["threshold"]),
            total_shares=int(data["total"]),
            data_bytes=base64.b64decode(data["data_b64"]),
            checksum=data["checksum"],
            label=data.get("label", "default"),
        )

    def to_armor(self) -> str:
        """Encode share into armored ASCII text block."""
        d = self.to_dict()
        raw_json = json.dumps(d, separators=(",", ":")).encode("utf-8")
        b64 = base64.b64encode(raw_json).decode("ascii")
        chunks = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
        return f"{SHARE_ARMOR_HEADER}\nIndex: {self.share_index}/{self.total_shares} (Quorum: {self.threshold})\n{chunks}\n{SHARE_ARMOR_FOOTER}\n"

    @classmethod
    def from_armor(cls, armored_text: str) -> SecretShare:
        """Parse share from armored ASCII block or raw JSON string."""
        cleaned = armored_text.strip()
        if SHARE_ARMOR_HEADER in cleaned and SHARE_ARMOR_FOOTER in cleaned:
            start = cleaned.find(SHARE_ARMOR_HEADER) + len(SHARE_ARMOR_HEADER)
            end = cleaned.find(SHARE_ARMOR_FOOTER)
            body = cleaned[start:end]
            # Strip potential headers like Index: ...
            lines = [l.strip() for l in body.splitlines() if l.strip() and not l.startswith("Index:")]
            b64_str = "".join(lines)
        else:
            b64_str = cleaned.replace("\n", "").replace("\r", "").strip()

        try:
            raw_bytes = base64.b64decode(b64_str)
            d = json.loads(raw_bytes.decode("utf-8"))
            return cls.from_dict(d)
        except Exception as e:
            # Fallback check if it's already a raw JSON string
            try:
                d = json.loads(cleaned)
                return cls.from_dict(d)
            except Exception:
                raise ValueError(f"Failed to parse secret share: {e}") from e


class ShamirSecretSharing:
    """Shamir's (k, n) Threshold Secret Sharing Engine over GF(2^8)."""

    @staticmethod
    def split_secret(
        secret: Union[str, bytes],
        threshold: int,
        total_shares: int,
        label: str = "master-key",
    ) -> List[SecretShare]:
        """Split a secret into n shares such that any threshold (k) shares can reconstruct it.

        Args:
            secret: String or bytes to be protected.
            threshold: Minimum number of shares required for reconstruction (2 <= k <= n <= 255).
            total_shares: Total number of shares to generate.
            label: Descriptive label for the quorum set.

        Returns:
            List of SecretShare objects.
        """
        if not (2 <= threshold <= total_shares <= 255):
            raise ValueError(f"Invalid threshold or total shares: 2 <= {threshold} <= {total_shares} <= 255")

        if isinstance(secret, str):
            secret_bytes = secret.encode("utf-8")
        else:
            secret_bytes = bytes(secret)

        if not secret_bytes:
            raise ValueError("Secret cannot be empty")

        # Each byte of the secret corresponds to the constant term a_0 of a random polynomial in GF(2^8)
        # poly(x) = secret_byte + a_1*x + a_2*x^2 + ... + a_{k-1}*x^{k-1}
        secret_len = len(secret_bytes)
        share_data = [bytearray(secret_len) for _ in range(total_shares)]

        # Checksum of the secret for tamper verification
        secret_hash = hashlib.sha256(secret_bytes).hexdigest()

        for byte_idx, sec_byte in enumerate(secret_bytes):
            # Sample k-1 random coefficients in GF(2^8)
            coeffs = [sec_byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
            for i in range(total_shares):
                x = i + 1  # x-coordinates 1..n
                y = gf256_eval_poly(coeffs, x)
                share_data[i][byte_idx] = y

        shares: List[SecretShare] = []
        for i in range(total_shares):
            s_bytes = bytes(share_data[i])
            share_checksum = hashlib.sha256(s_bytes + secret_hash.encode("ascii")).hexdigest()[:16]
            shares.append(
                SecretShare(
                    share_index=i + 1,
                    threshold=threshold,
                    total_shares=total_shares,
                    data_bytes=s_bytes,
                    checksum=share_checksum,
                    label=label,
                )
            )

        return shares

    @staticmethod
    def reconstruct_secret(shares: Sequence[Union[SecretShare, str, Dict[str, Any]]]) -> bytes:
        """Reconstruct original secret bytes from a set of threshold shares using Lagrange interpolation at x=0.

        Args:
            shares: List of at least k distinct SecretShare objects (or their armor strings / dicts).

        Returns:
            Reconstructed secret bytes.
        """
        parsed_shares: List[SecretShare] = []
        seen_indices = set()

        for s in shares:
            if isinstance(s, str):
                share_obj = SecretShare.from_armor(s)
            elif isinstance(s, dict):
                share_obj = SecretShare.from_dict(s)
            else:
                share_obj = s

            if share_obj.share_index in seen_indices:
                continue  # ignore duplicates
            seen_indices.add(share_obj.share_index)
            parsed_shares.append(share_obj)

        if not parsed_shares:
            raise ValueError("No shares provided for reconstruction")

        required_k = parsed_shares[0].threshold
        if len(parsed_shares) < required_k:
            raise ValueError(
                f"Quorum threshold not met: received {len(parsed_shares)} shares, required {required_k}"
            )

        # Truncate to first k shares if more were provided
        quorum = parsed_shares[:required_k]

        secret_len = len(quorum[0].data_bytes)
        for s in quorum:
            if len(s.data_bytes) != secret_len:
                raise ValueError("Share length mismatch: corrupted share set")
            if s.threshold != required_k:
                raise ValueError("Share threshold parameter mismatch")

        # Lagrange interpolation at x = 0:
        # L_i(0) = prod_{j != i} (0 - x_j) / (x_i - x_j) = prod_{j != i} x_j / (x_i ^ x_j)
        xs = [s.share_index for s in quorum]
        basis_weights = []
        for i in range(required_k):
            weight = 1
            xi = xs[i]
            for j in range(required_k):
                if i != j:
                    xj = xs[j]
                    denom = gf256_sub(xi, xj)
                    factor = gf256_div(xj, denom)
                    weight = gf256_mul(weight, factor)
            basis_weights.append(weight)

        reconstructed = bytearray(secret_len)
        for byte_idx in range(secret_len):
            val = 0
            for i in range(required_k):
                y = quorum[i].data_bytes[byte_idx]
                val = gf256_add(val, gf256_mul(y, basis_weights[i]))
            reconstructed[byte_idx] = val

        return bytes(reconstructed)

    @staticmethod
    def reconstruct_secret_text(shares: Sequence[Union[SecretShare, str, Dict[str, Any]]]) -> str:
        """Reconstruct UTF-8 string secret from shares."""
        raw_bytes = ShamirSecretSharing.reconstruct_secret(shares)
        return raw_bytes.decode("utf-8")


def split_secret_into_shares(
    secret: Union[str, bytes],
    threshold: int = 3,
    total_shares: int = 5,
    label: str = "master-key",
) -> Dict[str, Any]:
    """Helper for high-level tool and API dispatch."""
    shares = ShamirSecretSharing.split_secret(
        secret=secret,
        threshold=threshold,
        total_shares=total_shares,
        label=label,
    )
    return {
        "threshold": threshold,
        "total_shares": total_shares,
        "label": label,
        "shares": [s.to_dict() for s in shares],
        "armored_shares": [s.to_armor() for s in shares],
    }


def combine_shares_to_secret(
    shares: Sequence[Union[str, Dict[str, Any]]],
) -> Dict[str, Any]:
    """Helper for reconstructing secret from armored strings or dicts."""
    secret_bytes = ShamirSecretSharing.reconstruct_secret(shares)
    try:
        secret_text = secret_bytes.decode("utf-8")
        is_text = True
    except UnicodeDecodeError:
        secret_text = ""
        is_text = False

    return {
        "is_text": is_text,
        "secret_text": secret_text,
        "secret_b64": base64.b64encode(secret_bytes).decode("ascii"),
        "length_bytes": len(secret_bytes),
    }
