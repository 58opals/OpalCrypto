# Metal Readiness

This document records the July 11, 2026 Apple Silicon Metal performance spike for public Schnorr verification and its production qualification. The benchmark kernel and packaged production path passed their cached-key and varying-key evidence gates on the available M1 Max. The Swift CPU verifier remains the correctness source and portable fallback. Automatic Metal selection is qualified only for the exact M1 Max profile recorded below.

## Current Decision

- **Benchmark go:** all five cached-key and all five varying-key release processes exceeded 2x end-to-end CPU/Metal throughput at 8,192 records, and Metal beat multicore Swift at 4,096 in every process.
- **CPU production go:** `OpalCrypto.Signature.Schnorr.VerificationBatch` provides ordered cached-key and varying-key verification through optimized multicore Swift.
- **Narrow Metal production go:** the shader is packaged as a precompiled SwiftPM resource and the production runtime is constrained to public inputs, bounded reusable buffers, one-time parity self-test, and explicit failure handling. The production API passed its five-process gate, so `.automatic` may select Metal on the exact qualified M1 Max profile.
- **Marketing no-go:** do not add a README claim or general Apple Silicon performance claim. One Mac and one toolchain are not product evidence.

The measured crossover for both key modes is greater than 1,024 and no higher than 4,096 records. The benchmark did not sample 2,048, so it does not support a narrower break-even claim.

## Scope And Correctness Boundary

The benchmark compares the Metal path with package-internal serial and multicore Swift operations that use the same internal Schnorr verifier as the public API while bypassing per-record diagnostics. Parallel verification preserves result order and uses uniformly balanced throwing-task-group chunks, at most `activeProcessorCount` workers, and at least 128 records per task.

Signing and fixture construction stay outside timing. Cached-key preparation builds only record-varying challenge data. Warm varying-key verification uses prepared tables; the fair CPU and Metal varying-key end-to-end cases both start with the same raw public-key bytes and include parsing and table construction. The Metal case also includes structure-of-arrays packing and a fresh table upload.

Every benchmark and validation output is compared with the Swift result. A command-buffer status other than `.completed`, a preparation failure, or any output mismatch throws and fails the process. In production, the qualified Metal backend runs fixed known-answer self-tests after pipeline creation and then treats binary GPU output as authoritative; it does not repeat each batch on the CPU. Signing, nonces, private scalars, ECDH, reusable-payment-address scan keys, and other secret-bearing operations remain out of scope.

## Measurement Environment

| Property | Value |
| --- | --- |
| Computer | MacBook Pro 18,2 |
| SoC | Apple M1 Max |
| CPU | 10 cores reported by `activeProcessorCount` (8 performance, 2 efficiency) |
| GPU | 32-core Apple GPU, Metal family `apple7` |
| Memory | 64 GB |
| OS | macOS 26.5.2, build 25F84 |
| Swift | Apple Swift 6.3.2, swiftlang 6.3.2.1.108, clang 2100.1.1.101 |
| Target | arm64-apple-macosx26.0, release configuration |
| Power/thermal | Low Power Mode disabled; thermal state nominal in every evidence process |
| Pipeline width | `threadExecutionWidth` 32; supported sweep widths 64, 128, and 256 |

The requested 512-thread candidate exceeded the pipeline's valid maximum and was not dispatched. Across the five cached-key processes, mean 8,192-record warm times were 128.521 ms at width 64, 127.569 ms at width 128, and 128.183 ms at width 256. Width 128 is therefore the retained default.

## Implementation Under Test

The optimized benchmark kernel uses fixed eight-limb, 32-bit Comba multiplication; bounded secp256k1 pseudo-Mersenne reduction; symmetry-specialized squaring; and a fixed addition chain for the `(p + 1) / 4` quadratic-residue exponent. The implementation was derived independently; no code was copied from UltrafastSecp256k1.

CPU-prepared signed WNAF digits use component/index-major `Int8` structure-of-arrays storage so adjacent GPU threads read adjacent records. Cached generator/key tables are immutable uploads. Varying-key verification uses width-3 key WNAF, shares one generator table, and stores per-record public-key tables slot-major. Preparation batches affine conversion across each parallel chunk and derives the endomorphism table from the converted base table. Shared Metal buffers grow to bounded capacities and are reused across warm dispatches.

The validator covers 36 boundary pairs plus 10,000 deterministic generated field pairs for multiplication, squaring, and quadratic-residue parity; 9,979 generated operands are in the upper half of the field. It also covers all 16 Bitcoin Cash Schnorr vectors; an 8,192-record generated cached-key corpus with digest and signature corruption; an 8,192-record wrong-public-key pass; and a 256-record distinct-key corpus with public-key, digest, and signature corruption.

## Production Qualification Boundary

The production API verifies each record independently and returns one ordered Boolean result per input. `.cpu` always uses the optimized Swift implementation. `.metal` requires a qualified Metal profile, runs even below the automatic crossover, and never falls back. `.automatic` uses CPU for empty or small workloads, unqualified devices and platforms, Low Power Mode, and serious or critical thermal state. On a qualified profile, its warm Metal threshold is 4,096 records and its cold threshold is 8,192 when pipeline initialization and self-test have not been paid.

For `.automatic`, a non-cancellation Metal failure discards every GPU result and recomputes the complete batch on CPU. Cancellation propagates without fallback. Forced `.metal` reports an unavailable or failed public batch error and never returns partial results. The initial qualification envelope is macOS, exact Metal device name `Apple M1 Max`, and Apple GPU family 7. Unknown devices, other Apple GPU families, and other platforms are unqualified and stay on CPU under `.automatic`.

Production diagnostics emit only aggregate policy, backend, input-shape, count, timing, and stable failure-reason fields. Stable Metal reasons are `metal_unavailable`, `metal_resource_missing`, `metal_pipeline_initialization_failed`, `metal_allocation_failed`, `metal_command_failed`, and `metal_invalid_output`. Signatures, digests, public keys, device names, driver strings, record indices, and per-record results are never diagnostic fields. A mixed valid/invalid batch is a successful operation, not a backend failure.

The production qualification is **passed for the exact recorded M1 Max profile**. Benchmark-kernel evidence alone did not enable routing; the separate public production-API gate below did.

## Commands

Build and correctness validation:

```bash
swift build -c release
swift test
OPALCRYPTO_RUN_PERF_TESTS=1 swift test
swift run -c release OpalCryptoBenchmarks -- --validate-metal
```

Five fresh cached-key release processes, each with two warmups and five measured samples:

```bash
for run in 1 2 3 4 5; do
  swift run -c release OpalCryptoBenchmarks -- --suite metal --warmups 2 --samples 5 --output ".build/opalcrypto-benchmarks/spike-gate-cached-run-${run}.jsonl"
done
```

Five fresh varying-key release processes after the cached gate passed:

```bash
for run in 1 2 3 4 5; do
  swift run -c release OpalCryptoBenchmarks -- --suite metal --filter "varying keys" --warmups 2 --samples 5 --output ".build/opalcrypto-benchmarks/spike-gate-varying-full-run-${run}.jsonl"
done
```

Focused production API, CPU-operation, and diagnostics validation:

```bash
swift test --filter PublicAPISchnorrBatchVerificationValidator
swift test --filter SchnorrBatchVerificationOperationValidator
swift test --filter DiagnosticsIntegrationValidator
```

Five fresh production-API release processes, covering cached and varying inputs through forced CPU and forced Metal policies:

```bash
for run in 1 2 3 4 5; do
  swift run -c release OpalCryptoBenchmarks -- --suite metal --filter "Production API" --warmups 2 --samples 5 --output ".build/opalcrypto-benchmarks/production-metal-qualified-run-${run}.jsonl"
done
```

Every production process must pass the same per-shape gate: Metal at least 2x CPU end-to-end throughput at 8,192 records and no slower than CPU at 4,096, with exact ordered result parity. Any mismatch, command failure, unexpected forced-Metal fallback, unbounded allocation, or regression against the retained kernel fails qualification. All five recorded processes passed.

Signing-disabled generic Xcode builds also passed for iOS, tvOS, visionOS, and watchOS. The first three compile the conditionally linked Metal target; watchOS compiles the same public batch API through the CPU-only library graph with no `OpalCryptoMetal` dependency. These compile checks do not certify non-macOS Metal profiles; that still requires real-device correctness and performance evidence.

Final validation passed `swift build -c release`, 273 tests in 38 suites under both the normal and opt-in performance configurations, and the exclusive Metal validator. The validator reported 10,036 field cases, all 16 Bitcoin Cash Schnorr vectors, 8,192-record generated and wrong-key corpora, and the 256-record distinct-key corpus with the stable checksum `-3088338677`.

## Production API Five-Process Evidence

These medians include public batch construction, result conversion, varying-key table preparation, dispatch, and readback. Fixtures and signing remain outside timing. Speedup is multicore Swift time divided by forced Metal time.

| Process | Cached 4,096 | Cached 8,192 | Varying 4,096 | Varying 8,192 |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 1.44x | 2.43x | 2.25x | 3.86x |
| 2 | 1.56x | 2.63x | 2.48x | 4.05x |
| 3 | 1.59x | 2.97x | 2.54x | 4.73x |
| 4 | 1.81x | 2.86x | 2.77x | 4.55x |
| 5 | 1.47x | 2.52x | 2.33x | 4.03x |

Across the five final-runtime processes, cached-key 8,192-record Metal medians were 135.368–142.541 ms versus 344.150–416.803 ms on CPU, a 2.43x–2.97x range. Varying-key Metal medians were 141.442–149.672 ms versus 564.489–706.890 ms on CPU, a 3.86x–4.73x range. At 4,096 records, cached Metal was 1.44x–1.81x faster and varying Metal was 2.25x–2.77x faster. The production gate therefore retains the measured automatic crossover as greater than 1,024 and no higher than 4,096.

## Before And After

The before artifact used the previous end-to-end cached-key Metal implementation with one warmup and three samples. The optimized figures below are the median of the five fresh-process medians. The optimized CPU column is the fair multicore verifier; the older serial diagnostic loop measured 286.509, 1,147.867, and 2,304.388 ms at 1,024, 4,096, and 8,192 respectively and is not used for the gate.

| Records | Before Metal end-to-end | Optimized Metal end-to-end | Optimized multicore Swift | CPU / Metal |
| ---: | ---: | ---: | ---: | ---: |
| 1,024 | 474.931 ms | 114.465 ms | 54.094 ms | 0.47x |
| 4,096 | 579.494 ms | 118.849 ms | 219.899 ms | 1.85x |
| 8,192 | 615.747 ms | 142.566 ms | 465.901 ms | 3.27x |

Cached-key preparation and warm-execution medians make the end-to-end composition explicit:

| Records | CPU prep | Warm Metal | End-to-end Metal | Multicore Swift | CPU / Metal |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 | 1.551 ms | 112.417 ms | 114.465 ms | 54.094 ms | 0.47x |
| 4,096 | 5.586 ms | 112.650 ms | 118.849 ms | 219.899 ms | 1.85x |
| 8,192 | 11.109 ms | 128.423 ms | 142.566 ms | 465.901 ms | 3.27x |

Varying-key medians report both prebuilt-key verification and the fair raw-key end-to-end comparison used by the gate:

| Records | Metal prep | Warm Metal | End-to-end Metal | CPU prebuilt keys | CPU raw-key end-to-end | Full CPU / Metal |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,024 | 15.262 ms | 106.724 ms | 121.044 ms | 64.167 ms | 108.153 ms | 0.89x |
| 4,096 | 49.291 ms | 106.475 ms | 156.498 ms | 204.250 ms | 376.241 ms | 2.40x |
| 8,192 | 93.617 ms | 122.590 ms | 215.950 ms | 414.616 ms | 706.875 ms | 3.27x |

## Five-Process Evidence Gate

Cached-key results:

| Process | Metal 4,096 | CPU 4,096 | CPU / Metal | Metal 8,192 | CPU 8,192 | CPU / Metal |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 119.799 ms | 219.323 ms | 1.83x | 142.811 ms | 541.295 ms | 3.79x |
| 2 | 118.849 ms | 217.595 ms | 1.83x | 140.138 ms | 533.707 ms | 3.81x |
| 3 | 118.047 ms | 257.027 ms | 2.18x | 142.566 ms | 450.837 ms | 3.16x |
| 4 | 118.365 ms | 219.899 ms | 1.86x | 146.102 ms | 399.125 ms | 2.73x |
| 5 | 119.204 ms | 305.810 ms | 2.57x | 138.331 ms | 465.901 ms | 3.37x |

Varying-key end-to-end results, with both sides starting from raw public-key bytes:

| Process | Metal 4,096 | CPU 4,096 | CPU / Metal | Metal 8,192 | CPU 8,192 | CPU / Metal |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 149.986 ms | 446.668 ms | 2.98x | 234.239 ms | 903.864 ms | 3.86x |
| 2 | 158.277 ms | 421.839 ms | 2.67x | 224.361 ms | 847.377 ms | 3.78x |
| 3 | 159.894 ms | 376.241 ms | 2.35x | 215.950 ms | 706.875 ms | 3.27x |
| 4 | 156.498 ms | 351.497 ms | 2.25x | 214.682 ms | 605.513 ms | 2.82x |
| 5 | 145.676 ms | 286.632 ms | 1.97x | 191.927 ms | 564.008 ms | 2.94x |

Every cached process passed the 8,192-record 2x gate with a 2.73x–3.81x range. Every corrected varying-key process passed with a 2.82x–3.86x range. Both modes beat their matching multicore Swift comparison at 4,096 in every process.

Cold pipeline initialization is reported separately from warm execution. The ten evidence-process metadata records measured 37.418–47.934 ms with the system driver cache already populated; that range is not a first-ever shader-compilation guarantee.

## Profiler Evidence

Before and after Metal System Trace and Game Performance captures use the same cached-key 8,192-record end-to-end filter:

```bash
BENCHMARK_BINARY="$(swift build -c release --show-bin-path)/OpalCryptoBenchmarks"
xctrace record --template "Metal System Trace" --output .build/opalcrypto-benchmarks/spike-after-metal.trace --launch -- "$BENCHMARK_BINARY" --suite metal --filter "Metal Schnorr verify end-to-end (cached key, 8192)" --warmups 1 --samples 3
xctrace record --template "Game Performance" --output .build/opalcrypto-benchmarks/spike-after-game-performance.trace --launch -- "$BENCHMARK_BINARY" --suite metal --filter "Metal Schnorr verify end-to-end (cached key, 8192)" --warmups 1 --samples 3
xctrace record --template "Metal System Trace" --output .build/opalcrypto-benchmarks/production-after-metal.trace --launch -- "$BENCHMARK_BINARY" --suite metal --filter "Production API Metal Schnorr verify (cached key, 8192)" --warmups 1 --samples 3
xctrace record --template "Game Performance" --output .build/opalcrypto-benchmarks/production-after-game-performance.trace --launch -- "$BENCHMARK_BINARY" --suite metal --filter "Production API Metal Schnorr verify (cached key, 8192)" --warmups 1 --samples 3
```

The ignored local captures are:

- Before: `.build/opalcrypto-benchmarks/spike-before-metal.trace` (272 MB) and `.build/opalcrypto-benchmarks/spike-before-game-performance.trace` (176 MB).
- After: `.build/opalcrypto-benchmarks/spike-after-metal.trace` (161 MB) and `.build/opalcrypto-benchmarks/spike-after-game-performance.trace` (175 MB).
- Production API: `.build/opalcrypto-benchmarks/production-after-metal.trace` (163 MB) and `.build/opalcrypto-benchmarks/production-after-game-performance.trace` (158 MB).

The production captures used the forced-Metal cached-key public API at 8,192 records with one warmup and three samples. Their table of contents includes Metal command-buffer, GPU-interval, allocation, and GPU-counter schemas, and the benchmark process exited successfully. The captures preserve profiling evidence but do not support a portable GPU-counter claim.

## Final Boundary And Next Gate

The result is a **go for the public CPU batch API and automatic production Metal on the exact recorded M1 Max profile**. Broader device certification and marketing remain a **no-go** until cross-device Apple Silicon measurements, mobile and other supported-platform validation, and sustained real-caller evidence exist.

The production result may be described narrowly as: on the recorded M1 Max configuration, five fresh release processes showed 2.43x–2.97x cached-key and 3.86x–4.73x varying-key end-to-end throughput at 8,192 public Schnorr records versus the matching multicore Swift path. It must not be promoted to README or general product marketing in this round.

## Non-Goals

- No C, C++, CUDA, or external cryptography backend.
- No automatic Metal enablement outside the exact qualified M1 Max profile.
- No Metal certification beyond the exact recorded M1 Max profile in this round.
- No committed benchmark JSONL or Instruments artifact.
- No GPU signing, nonce generation, private scalar handling, ECDH, reusable-payment-address scanning, or other secret-bearing work.
- No claim about iPhone, iPad, other Macs, other Apple GPU families, or sustained production workloads.

## Superseded Probe Evidence

Earlier Stage 5 records measured a command/readback probe that did not execute secp256k1 verification on GPU, followed by a first real-core implementation and a single-run end-to-end prototype. A provisional varying-key run also packed tables from already-constructed verification keys and therefore did not satisfy the full-preparation boundary. Those historical/provisional results are not the current gate. The corrected July 11 five-process tables above are the source of truth for this spike.
