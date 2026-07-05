# Metal Readiness

This document records the current CPU-to-Metal decision point for Opal Crypto performance work. The repository contains a benchmark-only Metal probe for public verification batches; it is not a production Metal verifier and it is not an accepted acceleration path.

## Current Decision

Metal planning is justified after two consecutive CPU-only plateau checks failed to produce a 10% targeted win:

- Stage 4 arithmetic experiment: a 5-bit sliding-window field/scalar exponentiation experiment regressed `Field sqrt`, `Field quadratic-residue check`, and `Scalar inversion`, so it was reverted.
- Stage 4B public-batch allocation experiment: direct parsing from typed private keys improved `Batch compressed public-key derivation (256)` by only about 2.1% and regressed 1024-key and forced-mode benchmarks, so it was reverted.

The accepted Swift CPU path remains the correctness source of truth and the fallback.

## Stage 5 Probe Result

The first Stage 5 implementation adds CPU batch verification baselines and a benchmark-only Metal probe for public-data cached ECDSA and Schnorr verification batches. The probe validates Metal command setup, buffer transfer, scheduling, synchronization, readback, and CPU-side parity checking over CPU verification results. It does not execute secp256k1 verification on GPU, so it cannot be accepted as a Metal acceleration path even if timing noise occasionally looks favorable.

Captured artifacts:

- CPU ECDSA batch baseline: `.build/opalcrypto-benchmarks/metal-stage5-cpu-ecdsa-batch.jsonl`
- CPU Schnorr batch baseline: `.build/opalcrypto-benchmarks/metal-stage5-cpu-schnorr-batch.jsonl`
- Metal probe run 1: `.build/opalcrypto-benchmarks/metal-stage5-metal-probe-batch.jsonl`
- Metal probe run 2: `.build/opalcrypto-benchmarks/metal-stage5-metal-probe-batch-run2.jsonl`

Run 2 compared with the CPU baselines:

| Workload | CPU median avg | Metal probe median avg | Delta |
| --- | ---: | ---: | ---: |
| Batch ECDSA verify digest (cached key, 256) | 72098.056 us | 73198.875 us | +1.5% |
| Batch ECDSA verify digest (cached key, 1024) | 287918.542 us | 286731.458 us | -0.4% |
| Batch Schnorr verify (cached key, 256) | 65412.403 us | 65641.014 us | +0.3% |
| Batch Schnorr verify (cached key, 1024) | 264647.292 us | 261269.125 us | -1.3% |

Decision: no-go for Metal acceleration in this slice. The probe does not perform GPU secp256k1 verification and does not demonstrate a 10% end-to-end win across two release runs. Keep Swift CPU as the default and only fallback path.

## Candidate Selection

Under the current no-secret-bearing-GPU boundary, the first Metal prototype candidate should be public batch verification, not private-key public-key derivation.

Public-key derivation remains an important CPU benchmark, but its input includes private scalars. Moving private-key derivation to GPU needs a separate review of memory residency, command-buffer lifetime, timing behavior, device sharing, capture/debug tooling, and failure cleanup. That review is outside the current readiness gate.

Batch verification remains the cleaner future candidate because signatures, digests, and public keys are public-data inputs. A future accepted prototype must implement the secp256k1 verification core in Metal and compare the existing Swift verification loop against that Metal kernel without changing public library APIs.

Receiver scanning for reusable payment addresses is a separate candidate class. It may be valuable as Apple Silicon acceleration for local bulk historical catch-up, but it is not eligible from the current Opal Crypto proxy benchmark alone. Opal Base must first provide an end-to-end benchmark that separates candidate loading, public-key construction, batch shared-secret derivation, matching, address or locking script derivation, wallet state, persistence, and indexer I/O. A receiver-scan Metal prototype is justified only if that benchmark shows Opal Crypto shared-secret derivation dominates at restore scale after ordinary CPU and pipeline tuning.

Any receiver-scan Metal backend is secret-bearing because scan private-key scalar material participates in GPU work. Before production use, it needs a security and product review covering GPU buffer residency, command-buffer lifetime, memory clearing limits, debug capture exposure, device sharing, timing behavior, failure cleanup, and CPU fallback behavior.

## Prototype Scope

The Stage 5 prototype should stay benchmark-target-only until it proves an end-to-end win:

- Add benchmark-only CPU batch verification workloads for ECDSA cached-key verification and Schnorr cached-key verification.
- Add a platform-gated Metal prototype path for the same public-data verification workload.
- Keep the Swift CPU implementation as the reference result and fallback.
- Compare every Metal result against the Swift CPU result for exact boolean parity.
- Exclude private-key signing, nonce generation, scalar inversion for secrets, and private-key public-key derivation unless a separate secret-handling review approves them.

## Acceptance Bar

Before any Metal path can move beyond prototype status, capture a same-machine CPU reference artifact:

```bash
swift run -c release OpalCryptoBenchmarks -- --suite hot --filter "cached key" --output .build/opalcrypto-benchmarks/metal-cpu-reference-cached-verification.jsonl
```

Then capture the Metal prototype artifact with the same workload shape. The Metal path is acceptable only if all of the following are true:

- It beats the improved Swift CPU path end-to-end by at least 10% on the targeted batch verification workload.
- The timing includes buffer setup, data transfer, command encoding, command scheduling, synchronization, result readback, and CPU-side result validation.
- It repeats the win in at least two separate release-mode benchmark runs on the same machine.
- It preserves exact verification results against the Swift CPU path.
- It introduces no public API changes and no `Package.swift` dependency changes.
- It remains platform-gated and falls back to Swift CPU when Metal is unavailable.

Kernel-only timing is not sufficient evidence.

## Non-Goals

- Do not add a C or C++ backend.
- Do not commit benchmark baseline artifacts.
- Do not make Metal the default path from a benchmark-only prototype.
- Do not send secret-bearing private-key, signing, nonce, or scalar material to GPU without a separate review.
- Do not encode reusable payment address scan policy, address management, transaction output matching, wallet state, persistence, or indexer integration in Opal Crypto.
