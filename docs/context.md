# Opal Crypto Context

This document keeps the durable, repo-owned context for Opal Crypto inside the package repository itself.

## Purpose and Role

Opal Crypto is the lowest-level cryptography package in the Swift stack. It exists so higher-level packages and apps can depend on one stable facade instead of coupling themselves to hashing, encoding, BCH, BIP340, or bounded RSA blind signatures, NIP-44 encrypted payloads, secure randomness, mnemonic, derivation, or large-integer implementation details.

The supported public contract is the `OpalCrypto` namespace. The package is intentionally narrow: it provides reusable low-level BCH primitives, focused BIP340 signing, and standards-bound NIP-44 encrypted payloads without absorbing app-domain or protocol/runtime concerns.

## Audience and Stakeholders

- Swift package and app authors who need BCH or BIP340 cryptography behind a stable facade.
- Higher-level packages that need reusable key, signature, hashing, secure-random, encoding, derivation, and numeric helpers.
- Product teams that need a disciplined crypto dependency under app-domain and protocol/runtime layers.

## Boundaries and Non-Goals

- In scope: facade-owned BCH cryptography, genuine BIP340 signing over typed 32-byte digests, bounded RFC 9474 RSA blind signatures, NIP-44 v2 encrypted payloads, secp256k1 keys, bounded secure randomness, batch shared-secret computation, hashing, encoding, PBKDF2 key derivation, and numeric helpers.
- Out of scope: wallet account orchestration, application-state management, reusable payment address policy, address management, mailbox routing, Nostr event schemas, protocol/runtime behavior, network transport, non-Swift scope, and exposing internal implementation models as supported API.
- Downstream code should depend on the public facade surface rather than internal source layout, implementation folders, or internal model names.

See [engineering-principles.md](engineering-principles.md) for the Swift-first implementation boundary, Apple-native acceleration policy, and benchmark-backed performance expectations. See [architecture-complexity-audit.md](architecture-complexity-audit.md) for the current ownership map and bounded cleanup backlog, [performance-roadmap.md](performance-roadmap.md) for staged CPU optimization, and [metal-readiness.md](metal-readiness.md) for the current Metal qualification boundary.

## Package Surfaces

- `OpalCrypto`: library target and the only supported downstream integration contract.
- `OpalCryptoBenchmarks`: executable target used for local benchmark and performance work.
- `OpalCryptoTests`: test target used to validate the package surface.
- The supported API lives behind the facade-first `OpalCrypto` namespace exposed under `Sources/OpalCrypto/PublicAPI`. Internal implementation folders are intentionally not part of the contract.

## Integration Expectations

- Use Opal Crypto directly when you need low-level BCH or BIP340 cryptographic primitives or related serialization helpers.
- Prefer the facade surface such as `OpalCrypto.Signature`, `OpalCrypto.RSABSSA`, `OpalCrypto.Nostr.NIP44`, `OpalCrypto.Key`, `OpalCrypto.Hashing`, `OpalCrypto.SecureRandom`, `OpalCrypto.Encoding`, `OpalCrypto.KeyDerivation`, `OpalCrypto.Numeric`, and `OpalCrypto.Secp256k1`.
- Move to higher-layer packages for wallet models, policy, history, transport, or protocol/runtime behavior.
- Do not rely on internal file names or internal model types remaining stable across package evolution.

## Current Focus

Keep the facade surface stable, easy to explain, and supported by concise examples and validation so downstream packages can adopt the toolkit without learning internal implementation details.
