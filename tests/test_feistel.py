import os
import secrets
import pytest

from feistel_cipher import FeistelCipher


def test_roundtrip_basic():
    key = b"mysecretkey"
    c = FeistelCipher(key, rounds=10, block_size=8)
    pt = b"The quick brown fox jumps over the lazy dog"
    ct = c.encrypt(pt)
    assert ct != pt
    rt = c.decrypt(ct)
    assert rt == pt


def test_empty_plaintext():
    key = b"k"
    c = FeistelCipher(key, rounds=8, block_size=8)
    pt = b""
    ct = c.encrypt(pt)
    rt = c.decrypt(ct)
    assert rt == pt


def test_non_aligned_plaintext():
    key = b"anotherkey"
    c = FeistelCipher(key, rounds=12, block_size=8)
    pt = b"12345"  # not multiple of block
    ct = c.encrypt(pt)
    assert len(ct) % 8 == 0
    assert c.decrypt(ct) == pt


def test_random_data_roundtrip():
    key = secrets.token_bytes(16)
    c = FeistelCipher(key, rounds=14, block_size=8)
    for _ in range(10):
        n = secrets.choice(range(0, 64))
        pt = secrets.token_bytes(n)
        ct = c.encrypt(pt)
        assert c.decrypt(ct) == pt
