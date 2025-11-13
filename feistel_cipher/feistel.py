"""
Simple Feistel cipher implementation.

Not intended as a production-grade cipher. This is a compact, easy-to-read
implementation suitable for constrained IoT devices for educational/demo
purposes. Use established, reviewed cryptographic libraries for real-world
security-critical systems.

Features:
- Configurable block size (bytes) and rounds
- Simple key schedule (derives round keys using HMAC-SHA256)
- PKCS#7 padding for arbitrary-length messages
"""
from typing import Callable
import hashlib
import hmac


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len <= 0 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def _derive_round_keys(master_key: bytes, rounds: int, round_key_len: int) -> list[bytes]:
    """Derive per-round keys using HMAC-SHA256 in a simple KDF.

    This uses the master key as the HMAC key and generates round keys by
    computing HMAC(master_key, b"FEISTEL" || round_index).
    """
    keys = []
    for i in range(rounds):
        data = b"FEISTEL" + i.to_bytes(2, "big")
        digest = hmac.new(master_key, data, hashlib.sha256).digest()
        if round_key_len <= len(digest):
            keys.append(digest[:round_key_len])
        else:
            # extend by hashing digest||counter
            out = digest
            ctr = 1
            while len(out) < round_key_len:
                out += hmac.new(master_key, digest + ctr.to_bytes(1, "big"), hashlib.sha256).digest()
                ctr += 1
            keys.append(out[:round_key_len])
    return keys


class FeistelCipher:
    """Lightweight Feistel network cipher.

    Constructor:
      master_key: bytes-like secret used to derive round keys
      rounds: number of Feistel rounds (recommended >= 8)
      block_size: block size in bytes for the Feistel block (even number)

    API:
      encrypt(plaintext: bytes) -> bytes
      decrypt(ciphertext: bytes) -> bytes
    """

    def __init__(self, master_key: bytes, rounds: int = 16, block_size: int = 8):
        if block_size % 2 != 0:
            raise ValueError("block_size must be even")
        if rounds < 1:
            raise ValueError("rounds must be >= 1")
        self.master_key = bytes(master_key)
        self.rounds = rounds
        self.block_size = block_size
        self.half = block_size // 2
        # choose round key length equal to half-block size
        self.round_keys = _derive_round_keys(self.master_key, rounds, self.half)

    def _round_function(self, right: bytes, round_key: bytes) -> bytes:
        """A simple round function: SHA256(right || round_key), truncated.

        This is intentionally simple and fast; replace with a more robust PRF
        for production use.
        """
        h = hashlib.sha256()
        h.update(right)
        h.update(round_key)
        return h.digest()[: self.half]

    def _encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("block length mismatch")
        left = block[: self.half]
        right = block[self.half :]
        for rk in self.round_keys:
            f = self._round_function(right, rk)
            new_left = _xor_bytes(left, f)
            left, right = right, new_left
        return left + right

    def _decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("block length mismatch")
        left = block[: self.half]
        right = block[self.half :]
        # inverse rounds: apply round keys in reverse
        for rk in reversed(self.round_keys):
            f = self._round_function(left, rk)
            new_right = _xor_bytes(right, f)
            right, left = left, new_right
        return left + right

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt bytes -> ciphertext (bytes)."""
        data = _pkcs7_pad(plaintext, self.block_size)
        out = bytearray()
        for i in range(0, len(data), self.block_size):
            block = data[i : i + self.block_size]
            out += self._encrypt_block(block)
        return bytes(out)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt bytes -> plaintext (bytes). Raises ValueError on bad padding."""
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("ciphertext length must be multiple of block size")
        out = bytearray()
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i : i + self.block_size]
            out += self._decrypt_block(block)
        return _pkcs7_unpad(bytes(out), self.block_size)


if __name__ == "__main__":
    # small demo
    key = b"secretkey123456"
    c = FeistelCipher(key, rounds=12, block_size=8)
    pt = b"hello feistel"
    ct = c.encrypt(pt)
    rt = c.decrypt(ct)
    print("plaintext:", pt)
    print("ciphertext:", ct.hex())
    print("recovered:", rt)
