"""Simple CLI for feistel_cipher demo.

Usage:
  python cli.py encrypt <hex-plaintext>  # plaintext hex
  python cli.py decrypt <hex-ciphertext> # ciphertext hex

Example:
  python cli.py encrypt 68656c6c6f
"""
import sys
from feistel_cipher import FeistelCipher


def hextobytes(s: str) -> bytes:
    return bytes.fromhex(s)


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 1
    cmd = argv[1]
    data = hextobytes(argv[2])
    key = b"cli-demo-key-123"
    c = FeistelCipher(key, rounds=12, block_size=8)
    if cmd == "encrypt":
        ct = c.encrypt(data)
        print(ct.hex())
    elif cmd == "decrypt":
        pt = c.decrypt(data)
        print(pt.hex())
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
