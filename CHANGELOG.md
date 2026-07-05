# Changelog

## v0.1.0 - 2026-07-05

- Initial public developer-preview release of the facade-first `OpalCrypto` package.
- Added typed public namespaces for signatures, secp256k1 key operations, key material, hashing, encoding, PBKDF2 key derivation, and numeric helpers.
- Added ECDSA and Schnorr signing and verification, cached verification keys, WIF, BIP-39 mnemonic helpers, extended keys, Base58, Bech32-style Base32 primitives, and BCH-oriented hash helpers.
- Added a repeatable benchmark workflow with smoke, hot-path, and full suites plus JSONL artifact output for same-machine performance evidence.
- Landed the first CPU performance pass for batch public-key derivation and cached verification while keeping public APIs and dependencies unchanged.
- Documented the CPU-to-Metal readiness gate; Metal remains prototype-only and is not part of production acceleration in this release.
