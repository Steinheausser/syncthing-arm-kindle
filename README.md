# syncthing-arm: Syncthing v2.1.2 for Kindle with ARMv8/NEON crypto overlay

Stock Go has no 32-bit ARM (`GOARCH=arm`) assembly for SHA-256, ChaCha20, or
Poly1305. On the Kindle Basic (MT8110, dual-core Cortex-A53 running in 32-bit
AArch32 mode), Syncthing pulls were bottlenecked first by `sha256.blockGeneric`
and then by `TLS_CHACHA20_POLY1305_SHA256` record decryption (`58.3%` of
Syncthing CPU).

This folder builds a drop-in `syncthing` v2.1.2 binary for `linux/arm` using
`go build -overlay` (leaving the installed Go toolchain untouched) with three
assembly implementations:

1. **SHA-256 (`crypto/internal/fips140/sha256`)**: ARMv8 AArch32 crypto
   extension (`SHA256H`, `SHA256H2`, `SHA256SU0`, `SHA256SU1`), gated on
   `HWCAP2_SHA2`.
2. **ChaCha20 (`vendor/golang.org/x/crypto/chacha20`)**: 3-block (192-byte)
   interleaved NEON loop + 1-block (64-byte) NEON tail (`xorKeyStreamNEON`),
   keeping `bufSize = 64` so the 32-byte Poly1305 key derivation per TLS record
   computes only 1 block instead of 4. Gated on `cpu.ARM.HasNEON`.
3. **Poly1305 (`vendor/golang.org/x/crypto/internal/poly1305`)**: ARMv7
   32-bit radix-$2^{32}$ multiply-accumulate (`UMULL`/`UMLAL`) with VFPv3
   `D`-register key caching (`updateASM`), gated on `cpu.ARM.HasVFPv3`.

## Kindle benchmark results (`crypto-test`)

| Primitive | Stock Go (`GOARCH=arm`) | Patched (ARMv8 / NEON) | Speed-up |
|---|---:|---:|---:|
| `crypto/sha256` (128 KiB) | 15.1–17.6 MB/s | 321–379 MB/s | ~21x |
| `chacha20` (16 KiB) | ~12 MB/s | 117.2 MB/s | ~10x |
| `poly1305` (16 KiB) | 23.9 MB/s | 235.3 MB/s | ~9.8x |
| `chacha20poly1305.Open` (16 KiB TLS record) | 6.8–13.5 MB/s | 66.0–67.2 MB/s | ~5–10x |

In a 10 s CPU profile during a 128 MiB pull on the Kindle:
- Total Syncthing CPU dropped from **102.8%** (1 core pegged) to **48.6%**
  (network/I/O bound).
- TLS decryption (`xorKeyStreamNEON` + `updateASM`) dropped from **57.8%** of
  Syncthing's CPU (**59.2%** of a core) to **9.3%** of Syncthing's CPU
  (**4.5%** of a core).

## Build

Requires Go 1.27+, Zig 0.17+ (`zig cc`), Python 3, and Git:

```powershell
powershell -ExecutionPolicy Bypass -File syncthing-arm\build.ps1
```

Outputs:
- `syncthing-arm/out/crypto-test`: standalone on-device correctness & throughput test
- `syncthing-arm/out/syncthing-patched`: static `linux/arm` Syncthing v2.1.2 binary
