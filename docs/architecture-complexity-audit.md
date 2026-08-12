# Architecture Complexity Audit

This audit covers Opal Crypto at private/draft `cdbadf398bcfdb0d9a3c7cd655a0f65089337f80`. The package was structurally over-complex in a few bounded implementation and validation areas, but the facade-first dependency boundary and the security-critical state machines remain well placed. No repository-wide redesign is warranted.

## Ownership Map

| Concern | Authoritative owner | Boundary to preserve |
| --- | --- | --- |
| Supported cryptographic API, typed validation, public errors, and operation diagnostics | `Sources/OpalCrypto/PublicAPI` | Downstream packages depend on `OpalCrypto`, not implementation models. |
| Parsed keys, canonical scalars, curve points, encodings, and algorithm computation | Internal `Sources/OpalCrypto` models | Public wrappers validate before internal computation; raw secret material does not cross diagnostics. |
| Blind-signature nonce and request lifecycle | Blind-signature and RSABSSA state values | One-attempt consumption and exact key/request binding remain explicit. |
| Schnorr batch correctness | Swift CPU verifier | Metal remains an optional, device-qualified acceleration path with CPU fallback. |
| Metal shader artifact | `Sources/OpalCryptoMetal/MetalSchnorrBatchVerification.metal` through `MetalLibraryBuildPlugin` | Production and benchmark hosts now load the same packaged metallib; the hosts and their policy remain separate. |
| Performance evidence | `OpalCryptoBenchmarks` plus `docs/benchmarks.md` and `docs/metal-readiness.md` | Benchmarks measure and validate; they do not authorize routing by themselves. |

## Completed Cleanup

1. **One Metal shader authority.** The benchmark's embedded 707-line shader copy was deleted. Its independent host now consumes `OpalCryptoMetal`'s packaged library, so `--validate-metal` exercises the artifact shipped to production without changing the production plugin or runtime.
2. **One ECDSA lifecycle executor per operation.** Public raw-key and opaque `SigningKey` entry points now converge on one digest-signing executor. Message and digest verification converge on one verification executor. Success, failure, error mapping, and diagnostics no longer have branch-specific owners; the public API is unchanged.
3. **One generator-multiplication implementation.** The permanently enabled endomorphism path is direct. Its unreachable eight-bit fallback, tuning flag, calculated table, and 1,024-line committed table chunks were deleted. Known-answer and hardened arithmetic behavior remain unchanged.
4. **Current Swift executable isolation.** The benchmark entry point is explicitly main-actor isolated, matching the package's Swift 6.2 toolchain contract.

## Preserved Complexity

- Blind-signature and RSABSSA one-use state is security authority, not incidental ceremony.
- Secret-bearing diagnostics redaction and bounded allocation checks stay at public boundaries.
- Schnorr batch CPU fallback, device qualification, Metal self-test, and cancellation-aware execution leasing remain separate responsibilities.
- Public facade compatibility and source-compatible ECDSA message aliases remain intact.

## Ranked Backlog And Reopen Conditions

1. **P2 — Split RSABSSA operation validation into generation-free contract tests and an explicit real-key conformance suite.** Reopen when RSABSSA behavior changes, when focused feedback again performs key generation, or when the focused suite exceeds 15 seconds for fixture reasons. Budget: one test-list check, one generation-free filter, and one slow conformance filter at milestone validation.
2. **P2 — Consolidate repeated diagnostics test lookup and reset helpers.** Reopen with the next diagnostics-family change or when another validator duplicates the same record-matching sequence. Budget: one diagnostics filter and one full non-live suite.
3. **P2 — Consolidate Metal runtime resources and qualification into one explicit state.** Reopen only with the next Metal lifecycle or routing change. Budget: lifecycle, cancellation, allocation, policy, differential Metal validation, and the five-process production gate.
4. **P3 — Delete the superseded command/readback Metal probe.** Reopen when benchmark inventory changes. Budget: benchmark listing and smoke suite; no production requalification.
5. **P3 — Replace string-derived benchmark capabilities with explicit metadata.** Reopen when a Metal benchmark is added or renamed. Budget: benchmark listing, smoke, and Metal suite.
6. **P3 — Replace Base32's internal Boolean mode with an enum, remove test-only BIP32 helpers, and review dormant checksum code.** Reopen only when the corresponding codec, derivation, or hashing surface changes. Budget: one focused suite per touched family.
7. **P3 — Review compatibility numeric and low-level facade surface for removal.** Reopen only for an intentional breaking release after downstream usage evidence is available. Budget: API diff, downstream builds, migration notes, and full suites.

The stop condition for this pass is satisfied after the two selected P2 clusters, the safe generator deletion, bounded validation, and repository landing. The backlog is intentionally not implementation scope for this pass.
