"""Simulate an IoT device: read input (file or text), encrypt with AEAD wrapper,
and write the binary payload (IV||ciphertext||tag) to a file.

Usage examples:
  # encrypt literal text and write to out.bin
  python device_simulator.py --text "Hello IoT device" --out out.bin

  # encrypt a file
  python device_simulator.py --infile sample.bin --out out.bin

Note: This demo uses encrypt-then-MAC (HMAC-SHA256) via `feistel_cipher.aead`.
For production, use an audited AEAD primitive.
"""

import argparse
import binascii
import sys
from pathlib import Path

from feistel_cipher.aead import encrypt_then_mac


DEFAULT_ENC_KEY = b"enc-demo-key-1234"
DEFAULT_MAC_KEY = b"mac-demo-key-1234"


def parse_args():
    p = argparse.ArgumentParser(description="Device simulator: encrypt data and write binary payload")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--infile", help="Path to input file to encrypt")
    group.add_argument("--text", help="Literal text to encrypt")
    p.add_argument("--out", default="message.bin", help="Output file (binary) where IV||ct||tag will be written")
    p.add_argument("--enc-key", help="Encryption key in hex (optional)")
    p.add_argument("--mac-key", help="MAC key in hex (optional)")
    p.add_argument("--rounds", type=int, default=12, help="Feistel rounds (default 12)")
    p.add_argument("--block-size", type=int, default=8, help="Feistel block size in bytes (even, default 8)")
    return p.parse_args()


def load_key(hexstr, default):
    if hexstr is None:
        return default
    try:
        return binascii.unhexlify(hexstr)
    except Exception:
        print("Invalid hex for key", file=sys.stderr)
        sys.exit(2)


def find_repo_root(start_path=None):
    """Find project root by looking for the `feistel_cipher` folder.

    This allows running the script from a subdirectory (for example
    `c_src`) while resolving relative paths against the project root.
    """
    p = Path(start_path or Path.cwd()).resolve()
    for parent in [p] + list(p.parents):
        if (parent / 'feistel_cipher').exists():
            return parent
    return Path.cwd()


def main():
    args = parse_args()
    # Resolve infile/out relative to repository root when paths are relative.
    repo_root = find_repo_root()
    if args.infile:
        path = Path(args.infile)
        if not path.is_absolute():
            path = (repo_root / path).resolve()
        if not path.exists():
            print(f"Input file not found: {path}", file=sys.stderr)
            sys.exit(1)
        with path.open("rb") as f:
            plaintext = f.read()
        input_type = "file"
    else:
        plaintext = args.text.encode("utf-8")
        input_type = "text"

    enc_key = load_key(args.enc_key, DEFAULT_ENC_KEY)
    mac_key = load_key(args.mac_key, DEFAULT_MAC_KEY)

    payload = encrypt_then_mac(plaintext, enc_key, mac_key, rounds=args.rounds, block_size=args.block_size)
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = (repo_root / out_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as f:
        f.write(payload)

    # Human-friendly output for beginners
    print("\n=== Device Simulator Output (human-friendly) ===")
    print(f"Input type: {input_type}")
    if input_type == "text":
        print(f"Plaintext (utf-8): {args.text}")
    print(f"Plaintext (hex): {plaintext.hex()}")
    print("\nEncryption method: Feistel network (confidentiality) + HMAC-SHA256 (integrity)")
    print(f"Parameters: rounds={args.rounds}, block_size={args.block_size} bytes")
    print("Output format (binary file): [ IV || ciphertext || MAC ]")
    print(" - IV: random nonce generated per message (ensures different ciphertexts for same plaintext)")
    print(" - ciphertext: encrypted data (length is a multiple of block size due to padding)")
    print(" - MAC: HMAC-SHA256 tag (verifies message integrity and authenticity)")
    print(f"\nWrote encrypted payload to: {out_path} (total {len(payload)} bytes)")
    print(f" Breakdown: IV={len(payload[:12])} bytes, ciphertext={len(payload[12:-32])} bytes, tag={len(payload[-32:])} bytes")
    print(f"Payload sample (hex, first 64 chars): {payload.hex()[:64]}")
    print("=== End of output ===\n")


if __name__ == "__main__":
    main()
