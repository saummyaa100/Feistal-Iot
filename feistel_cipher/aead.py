"""AEAD-style wrapper (encrypt-then-MAC) for the Feistel cipher reference.

This provides a simple encrypt-then-MAC construction using HMAC-SHA256 for
integrity and the existing Feistel cipher for confidentiality. It's intended
for demonstration and testing on host. For production use, prefer a vetted
AEAD primitive (AES-GCM, ChaCha20-Poly1305) and secure key storage.
"""
from __future__ import annotations

import hmac
import hashlib
import secrets
from typing import Tuple

from .feistel import FeistelCipher


DEFAULT_IV_LEN = 12
DEFAULT_TAG_LEN = 32


def encrypt_then_mac(
    plaintext: bytes,
    enc_key: bytes,
    mac_key: bytes,
    rounds: int = 12,
    block_size: int = 8,
    iv: bytes | None = None,
) -> bytes:
    """Encrypt plaintext and append IV||ciphertext||tag.

    Returns the concatenated bytes. IV is generated with a secure RNG when
    not provided. Tag is HMAC-SHA256(mac_key, iv || ciphertext).
    """
    if iv is None:
        iv = secrets.token_bytes(DEFAULT_IV_LEN)
    if len(iv) < 1:
        raise ValueError("iv must be non-empty")
    cipher = FeistelCipher(enc_key, rounds=rounds, block_size=block_size)
    ciphertext = cipher.encrypt(plaintext)
    tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return iv + ciphertext + tag


def decrypt_then_verify(
    data: bytes,
    enc_key: bytes,
    mac_key: bytes,
    rounds: int = 12,
    block_size: int = 8,
    iv_len: int = DEFAULT_IV_LEN,
    tag_len: int = DEFAULT_TAG_LEN,
) -> bytes:
    """Verify tag and decrypt. Raises ValueError on verification or padding errors.

    Returns the plaintext bytes on success.
    """
    if len(data) < iv_len + tag_len:
        raise ValueError("data too short")
    iv = data[:iv_len]
    tag = data[-tag_len:]
    ciphertext = data[iv_len:-tag_len]
    expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("MAC verification failed")
    cipher = FeistelCipher(enc_key, rounds=rounds, block_size=block_size)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def split_message(data: bytes, iv_len: int = DEFAULT_IV_LEN, tag_len: int = DEFAULT_TAG_LEN) -> Tuple[bytes, bytes, bytes]:
    """Helper to split data into (iv, ciphertext, tag)."""
    iv = data[:iv_len]
    tag = data[-tag_len:]
    ciphertext = data[iv_len:-tag_len]
    return iv, ciphertext, tag


__all__ = ["encrypt_then_mac", "decrypt_then_verify", "split_message"]
