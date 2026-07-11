# Changelog

## v0.1.3 - 2026-07-11

- Added ordered batch shared-secret derivation with automatic serial or parallel CPU execution for higher-level scan workloads.
- Added immutable BCH Schnorr verification batches with ordered per-record results, optimized CPU execution, and explicit `.automatic`, `.cpu`, and `.metal` policies; this is not probabilistic aggregate verification.
- Added production Metal acceleration qualified only for macOS on the exact `Apple M1 Max` device name with Apple GPU family 7; other profiles remain on the CPU under `.automatic`.
- Reduced allocation and copy work at batch public-key and shared-secret boundaries while preserving public API behavior and execution thresholds.
- Hardened cancellation, Metal lifecycle and output handling, public API contracts, benchmark coverage, and aggregate privacy-safe diagnostics.

## v0.1.0 - 2026-07-05

- Initial public developer-preview release of the facade-first `OpalCrypto` package.
- Added typed public namespaces for signatures, secp256k1 key operations, key material, hashing, encoding, PBKDF2 key derivation, and numeric helpers.
- Added ECDSA and Schnorr signing and verification, cached verification keys, WIF, BIP-39 mnemonic helpers, extended keys, Base58, Bech32-style Base32 primitives, and BCH-oriented hash helpers.
- Added a repeatable benchmark workflow with smoke, hot-path, and full suites plus JSONL artifact output for same-machine performance evidence.
- Landed the first CPU performance pass for batch public-key derivation and cached verification while keeping public APIs and dependencies unchanged.
- Documented the CPU-to-Metal readiness gate; Metal remains prototype-only and is not part of production acceleration in this release.
