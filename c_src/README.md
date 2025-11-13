# Feistel C demo

This folder contains a compact C prototype of the Feistel cipher used for
educational/IoT prototyping. It includes a tiny SHA-256 and HMAC used to
derive round keys and the round function. Replace the hash with hardware
accelerated primitives in production.

Build (host, requires gcc or clang):

```powershell
# Using gcc on Windows (mingw) or WSL
gcc -std=c11 -O2 -DFEISTEL_DEMO_MAIN feistel.c -o feistel_demo
./feistel_demo
```

Or with CMake:

```powershell
mkdir build; cd build
cmake ..
cmake --build . --config Release
.
```

Porting notes for MCU:
- Remove dynamic allocation (malloc/free) and replace with static buffers.
- Use hardware RNG and secure key storage when available.
- Provide a vetted SHA-256/HMAC implementation or use hardware crypto.
- Ensure stack usage fits on target; inline small buffers to avoid large stack frames.

Security note: This implementation is for prototyping and demonstration only.
Always use audited cryptographic libraries and authenticated encryption (AEAD)
for real IoT deployments.
