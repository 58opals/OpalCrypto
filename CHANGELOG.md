# Changelog

## Unreleased

- Made the Bitcoin Cash RFC6979 variant the default Schnorr nonce policy and deprecated the misleading BIP-340-named legacy policy.
- Bound Pedersen commitments to the canonical CashFusion base point and deprecated caller-selected setup points.
- Mapped invalid BIP-32 master scalars to the public `invalidDerivedKey` error.
- Required PBKDF2 callers to authorize an explicit HMAC-work budget, and made derivation cooperatively honor task cancellation before allocation and throughout pseudorandom-function rounds.
- Required explicit decoded-byte budgets for generic Base58 and byte-mode Base32 decoding, bounded fixed-format Base58Check imports with limit-specific errors, and rejected oversized DER signatures and mnemonic phrases before unbounded processing or compatibility normalization.
- Required explicit ciphertext-byte budgets for communication encryption, import, and decryption, with checked envelope-size arithmetic.
- Replaced the unbounded arbitrary-precision left shift and its legacy zero sentinel with a throwing operation that requires a result-byte budget.
- Made Metal benchmark initialization propagate unavailability instead of trapping, consolidated benchmark input preparation onto the production implementation, made fixture setup throw instead of trap, and made hardware-gated Metal tests report as skipped.
- Added independent Bitcoin Cash Schnorr and CashFusion Pedersen compatibility vectors.
- Added macOS CI, including a tagged-release gate against unstable dependencies.
- Updated `OpalDiagnostics` from its development branch to the stable `v0.2.0` release. The historical Opal Crypto `v0.1.3` tag remains branch-based, while future tags can use version-based resolution.
- Marked the preview as unsuitable for production key handling until secret-scalar operations complete constant-time hardening and security review.

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
