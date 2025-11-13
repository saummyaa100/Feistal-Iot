"""Receiver script: read a binary payload (IV||ciphertext||tag), verify and decrypt,
then print the recovered plaintext and metadata.

Usage:
  python receiver.py --in message.bin
"""

import argparse
from pathlib import Path
import binascii
import sys

from feistel_cipher.aead import decrypt_then_verify, split_message


DEFAULT_ENC_KEY = b"enc-demo-key-1234"
DEFAULT_MAC_KEY = b"mac-demo-key-1234"


def parse_args():
    p = argparse.ArgumentParser(description="Receiver: read file, verify and decrypt payload")
    p.add_argument("--in", dest="infile", required=True, help="Input binary file containing IV||ciphertext||tag")
    p.add_argument("--enc-key", help="Encryption key in hex (optional)")
    p.add_argument("--mac-key", help="MAC key in hex (optional)")
    p.add_argument("--rounds", type=int, default=12, help="Feistel rounds (default 12)")
    p.add_argument("--block-size", type=int, default=8, help="Feistel block size in bytes (default 8)")
    return p.parse_args()


def load_key(hexstr, default):
    if hexstr is None:
        return default
    try:
        return binascii.unhexlify(hexstr)
    except Exception:
        print("Invalid hex for key", file=sys.stderr)
        sys.exit(2)


def main():
    args = parse_args()
    path = Path(args.infile)
    if not path.exists():
        print("Input file not found:", args.infile, file=sys.stderr)
        sys.exit(1)
    data = path.read_bytes()
    enc_key = load_key(args.enc_key, DEFAULT_ENC_KEY)
    mac_key = load_key(args.mac_key, DEFAULT_MAC_KEY)

    # Explain what this program does for users unfamiliar with crypto
    print("\n=== Receiver: verifying and decrypting message ===")
    print("This program expects a binary file in the format: [ IV || ciphertext || MAC ]")
    print(" - IV: nonce used during encryption (public but must be unique per key)")
    print(" - ciphertext: encrypted message produced by the Feistel cipher")
    print(" - MAC: HMAC-SHA256 tag that ensures the message was not tampered with")

    try:
        plaintext = decrypt_then_verify(data, enc_key, mac_key, rounds=args.rounds, block_size=args.block_size)
    except Exception as e:
        print("Decryption/verification failed:", str(e), file=sys.stderr)
        print("The MAC check failed or the ciphertext/padding is invalid. Do NOT trust the data.")
        sys.exit(3)

    iv, ciphertext, tag = split_message(data)
    print(f"\nInput file: {path}")
    print(f"IV (hex): {iv.hex()} ({len(iv)} bytes)")
    print(f"Ciphertext size: {len(ciphertext)} bytes (always a multiple of block size due to padding)")
    print(f"Tag (hex): {tag.hex()} ({len(tag)} bytes)")
    try:
        text = plaintext.decode("utf-8")
        print(f"\nRecovered plaintext (utf-8): {text}")
    except Exception:
        print(f"\nRecovered plaintext (hex): {plaintext.hex()}")
    print("\nVerification: MAC matched and ciphertext was decrypted successfully — data is authentic and confidential.")
    print("=== End of output ===\n")


if __name__ == "__main__":
    main()
