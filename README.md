# Feistel Cipher (lightweight) for IoT demo

This repository contains a small, easy-to-read Feistel cipher implementation
written in Python. It's intended for educational or prototype use on constrained
devices. Do NOT use this as a drop-in replacement for standard, audited
cryptography in production.

Files:
- `feistel_cipher/feistel.py`: implementation of `FeistelCipher` class
- `tests/test_feistel.py`: pytest unit tests

Quick example (PowerShell):

```powershell
python -c "from feistel_cipher import FeistelCipher; c=FeistelCipher(b'secret',rounds=12,block_size=8); ct=c.encrypt(b'hello world'); print(ct.hex()); print(c.decrypt(ct))"
```

Run tests (PowerShell):

```powershell
python -m pip install pytest; pytest -q
```

Notes:
- The implementation uses HMAC-SHA256 to derive round keys and SHA256 in the
  round function. Both are chosen for simplicity and portability.
- Adjust `rounds` and `block_size` depending on platform constraints. More
  rounds increase security at the cost of CPU time.
