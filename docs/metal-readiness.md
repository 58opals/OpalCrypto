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

## Stage 5 Real-Core Starting Point

A follow-up benchmark-only prototype adds a public-data Schnorr verification core that performs secp256k1 field arithmetic, signed WNAF point multiplication, point addition, and the Schnorr candidate X/Jacobi checks in Metal. CPU-side benchmark support prepares the already-public signature/challenge WNAF digits and cached-key affine tables, then the Metal runtime validates every GPU result against the Swift CPU reference result.

This is a GPU-core milestone, not an accepted end-to-end acceleration path. On the first naive release-mode run, `Metal Schnorr verify core (cached key, 256)` measured about 483904 us per 256-record batch. After switching to CPU-prepared WNAF digits, affine tables, and nibble exponentiation for the residue check, the same 256-record core measured about 147992 us, versus about 67473 us for `Batch Schnorr verify (cached key, 256)`. At 1024 records, `Metal Schnorr verify core (cached key, 1024)` measured about 162419 us, versus about 280380 us for `Batch Schnorr verify (cached key, 1024)`.

Decision: keep the real-core Metal path benchmark-only. The 1024-record core result is the first useful GPU throughput signal, but acceptance still requires an end-to-end benchmark that includes CPU-side challenge preparation, WNAF/table preparation or caching policy, buffer setup, command scheduling, synchronization, readback, and CPU-side result validation across repeated release runs.

## Stage 5 End-to-End Batch Result

The next prototype step adds distinct Schnorr signatures and digests with a cached verification key, plus deliberate digest-mismatch negative records every 16th item. The Metal path now prepares per-record challenges and WNAF digits on CPU, reuses cached affine table words for the key, dispatches the Metal Schnorr core, reads back every result, and validates each result against the expected valid/invalid bit. Signing and fixture generation stay outside the measured operation. A follow-up width check moved the benchmark-only Metal WNAF path from width 6 to width 7, increasing cached odd multiples from 16 to 32 per component to reduce point additions.

Captured on July 8, 2026 in release mode:

| Workload | 1024 median | 4096 median | 8192 median |
| --- | ---: | ---: | ---: |
| Metal Schnorr prep (cached key) | 8.837 ms | 36.064 ms | 72.166 ms |
| Metal Schnorr end-to-end (cached key) | 464.752 ms | 561.923 ms | 594.464 ms |
| CPU Batch Schnorr distinct (cached key) | 291.627 ms | 1166.481 ms | 2324.008 ms |
| CPU / Metal end-to-end ratio | 0.63x | 2.08x | 3.91x |

Decision: still benchmark-only, but no longer a no-go on throughput. The end-to-end path loses at 1024 records because fixed Metal core and dispatch cost dominates, then wins at 4096 and 8192 records. This is not enough for acceptance because it is a single release-mode run and the speedup is still far below the original 450x target. A manual square-specialization experiment regressed end-to-end timing, while width 7 produced a modest repeatable win; the next engineering question is whether the Metal core can reduce its fixed cost and per-record field arithmetic cost enough to make medium batches profitable and large batches materially faster.

## Current Closeout

The Stage 5 Metal work should pause as a benchmark-only research artifact unless a product workload needs thousands of public Schnorr verifications in one batch. The current prototype proves that Apple Silicon Metal can beat the Swift CPU verifier for large public batches, but the best measured speedup is about 3.91x at 8192 records and the path still loses at 1024 records. That is not close to the original 450x target and does not justify production integration without a concrete large-batch caller.

Future work should be evidence-gated. Use Metal counters or Instruments before changing the kernel further, and only continue if profiling points to a specific bottleneck such as field multiplication occupancy, residue exponentiation, memory pressure from per-record digits, or command scheduling overhead. Keep the CPU verifier as the accepted path and keep this Metal code benchmark-target-only.

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
