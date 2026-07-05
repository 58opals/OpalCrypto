# Opal Crypto Context

This document keeps the durable, repo-owned context for Opal Crypto inside the package repository itself.

## Purpose and Role

Opal Crypto is the lowest-level BCH cryptography package in the Swift stack. It exists so higher-level packages and apps can depend on one stable facade instead of coupling themselves to hashing, encoding, secp256k1, mnemonic, derivation, or large-integer implementation details.

The supported public contract is the `OpalCrypto` namespace. The package is intentionally narrow: it provides the reusable low-level crypto surface for BCH-focused Swift software without absorbing app-domain or protocol/runtime concerns.

## Audience and Stakeholders

- Swift package and app authors who need BCH cryptography behind a stable facade.
- Higher-level BCH packages that need reusable key, signature, hashing, encoding, derivation, and numeric helpers.
- Product teams that need a disciplined crypto dependency under app-domain and protocol/runtime layers.

## Boundaries and Non-Goals

- In scope: facade-owned BCH cryptography for keys, secp256k1 signing and verification, batch shared-secret computation, hashing, encoding, PBKDF2 key derivation, and numeric helpers.
- Out of scope: wallet account orchestration, BCH application-state management, reusable payment address policy, address management, protocol/runtime behavior, network transport, non-BCH scope, non-Swift scope, and exposing internal implementation models as supported API.
- Downstream code should depend on the public facade surface rather than internal source layout, implementation folders, or internal model names.

See [engineering-principles.md](engineering-principles.md) for the Swift-first implementation boundary, Apple-native acceleration policy, and benchmark-backed performance expectations. See [performance-roadmap.md](performance-roadmap.md) for staged CPU optimization and [metal-readiness.md](metal-readiness.md) for the current Metal prototype gate.

## Package Surfaces

- `OpalCrypto`: library target and the only supported downstream integration contract.
- `OpalCryptoBenchmarks`: executable target used for local benchmark and performance work.
- `OpalCryptoTests`: test target used to validate the package surface.
- The supported API lives behind the facade-first `OpalCrypto` namespace exposed under `Sources/OpalCrypto/PublicAPI`. Internal implementation folders are intentionally not part of the contract.

## Integration Expectations

- Use Opal Crypto directly when you need low-level BCH cryptographic primitives or related serialization helpers.
- Prefer the facade surface such as `OpalCrypto.Signature`, `OpalCrypto.Key`, `OpalCrypto.Hashing`, `OpalCrypto.Encoding`, `OpalCrypto.KeyDerivation`, `OpalCrypto.Numeric`, and `OpalCrypto.Secp256k1`.
- Move to higher-layer packages for wallet models, policy, history, transport, or protocol/runtime behavior.
- Do not rely on internal file names or internal model types remaining stable across package evolution.

## Current Focus

Keep the facade surface stable, easy to explain, and supported by concise examples and validation so downstream packages can adopt the toolkit without learning internal implementation details.
