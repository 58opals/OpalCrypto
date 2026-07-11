# Benchmark Workflow

Opal Crypto benchmarks are same-machine evidence for performance-sensitive cryptography work. Treat them as decision support after correctness passes, not as universal timing claims across hardware, OS versions, toolchains, or thermal states.

See [performance-roadmap.md](performance-roadmap.md) for the CPU-to-Metal staging model and [metal-readiness.md](metal-readiness.md) for the current Metal readiness and production qualification gate.

## Correctness First

Run the normal test suite before trusting any performance result:

```bash
swift test
```

For changes touching batch derivation, cached-key verification, arithmetic shortcuts, or other performance-sensitive internals, also run the opt-in performance smoke validators:

```bash
OPALCRYPTO_RUN_PERF_TESTS=1 swift test
```

## Benchmark Commands

List the benchmarks selected by the default `full` suite:

```bash
swift run -c release OpalCryptoBenchmarks -- --list
```

Run a quick representative smoke benchmark:

```bash
swift run -c release OpalCryptoBenchmarks -- --suite smoke
```

Run hot-path cryptography benchmarks:

```bash
swift run -c release OpalCryptoBenchmarks -- --suite hot
```

Run the public-data Schnorr CPU/Metal comparison suite with the performance-spike evidence settings:

```bash
swift run -c release OpalCryptoBenchmarks -- --suite metal --warmups 2 --samples 5
```

Run the exclusive Metal correctness validator instead of a timed suite:

```bash
swift run -c release OpalCryptoBenchmarks -- --validate-metal
```

`--warmups` and `--samples` accept positive integers. Their defaults remain one warmup and three measured samples. `--validate-metal` cannot be combined with a suite, filter, list, output, warmup, or sample option.

Filter by benchmark name with a case-insensitive substring:

```bash
swift run -c release OpalCryptoBenchmarks -- --suite hot --filter Schnorr
```

Capture a JSONL artifact under the ignored SwiftPM build directory:

```bash
swift run -c release OpalCryptoBenchmarks -- --suite full --output .build/opalcrypto-benchmarks/full.jsonl
```

## Suites

- `smoke`: representative quick checks across public-key derivation, cached signature verification, PBKDF2, and encoding.
- `hot`: secp256k1 public-key derivation, batch derivation, batch shared-secret derivation, receiver-scan cryptographic proxy work, signature, cached-key, field/scalar arithmetic, and point multiplication benchmarks.
- `metal`: serial and multicore Swift Schnorr baselines, raw-key multicore end-to-end baselines, cached-key and varying-key Metal preparation, warm verification, end-to-end verification, and supported threadgroup-width sweeps.
- `full`: every benchmark in the executable target.

## Output

The executable keeps human-readable stdout summaries and emits JSONL records. Each run starts with a `benchmark_run` metadata record, emits one `benchmark` record per executed benchmark, and ends with a `benchmark_summary` record containing the executed benchmark count and checksum.

Schema-version 2 run metadata includes the Metal device and Apple GPU family, active CPU count, low-power and thermal state, Swift/OS/build metadata, pipeline thread-execution width, supported and selected threadgroup widths, and cold pipeline initialization time. Metal benchmark records also include per-sample CPU preparation, upload, dispatch/wait, readback/validation, key mode, record count, and threadgroup width.

When `--output` is provided, the same JSONL records are written to the requested path after creating parent directories. Keep generated artifacts under `.build/opalcrypto-benchmarks/` unless a task explicitly needs a different local path.

## Comparison Workflow

Use benchmarks as a before/after workflow on the same machine. Run a baseline from the target base branch, run the same suite and filter from the task branch, then compare benchmark names and median average time. A performance win is not valid if the correctness tests fail, benchmark filters differ, metadata shows a different toolchain or machine class, or the result only appears in one noisy sample.

The shared-secret receiver-scan benchmarks are cryptographic workload proxies only. Opal Base owns reusable payment address policy, address derivation, transaction output matching, wallet state, and indexer integration.

## Metal Performance-Spike Workflow

Signing and fixture construction happen before timing. The serial and parallel CPU cases call the same internal Schnorr verifier without public per-record diagnostics. Parallel work uses ordered, uniformly balanced task-group chunks, no more workers than `activeProcessorCount`, and at least 128 records per task. The Metal result remains acceptable only when every output bit matches the serial Swift result.

Capture the five fresh cached-key processes used by the evidence gate:

```bash
for run in 1 2 3 4 5; do
  swift run -c release OpalCryptoBenchmarks -- --suite metal --warmups 2 --samples 5 --output ".build/opalcrypto-benchmarks/spike-gate-cached-run-${run}.jsonl"
done
```

Only after that gate passes, capture the equivalent varying-key processes. These records report warm verification with prepared key tables plus fair CPU and Metal end-to-end cases that both begin with raw public-key bytes and include public-key parsing and table construction:

```bash
for run in 1 2 3 4 5; do
  swift run -c release OpalCryptoBenchmarks -- --suite metal --filter "varying keys" --warmups 2 --samples 5 --output ".build/opalcrypto-benchmarks/spike-gate-varying-full-run-${run}.jsonl"
done
```

The spike gate requires every process to show at least 2x CPU/Metal end-to-end speedup at 8,192 records and Metal no slower than multicore Swift at 4,096 records. A 1,024 loss paired with a 4,096 win records the measured crossover only as greater than 1,024 and no higher than 4,096; it does not locate a more precise break-even point.

Keep JSONL and Instruments traces under `.build/opalcrypto-benchmarks/`. They are ignored local evidence and must not be committed. The exact July 2026 M1 Max results and decision are recorded in [metal-readiness.md](metal-readiness.md).

## Production Schnorr Batch Qualification

The public `OpalCrypto.Signature.Schnorr.VerificationBatch` API and its multicore Swift backend are separate from the benchmark kernel. The packaged production path passed its five-process gate on the exact M1 Max profile recorded in [metal-readiness.md](metal-readiness.md). Prototype benchmark cases alone do not qualify `.automatic` to select Metal on any profile.

Run the focused API, CPU-operation, and aggregate-diagnostics checks first:

```bash
swift test --filter PublicAPISchnorrBatchVerificationValidator
swift test --filter SchnorrBatchVerificationOperationValidator
swift test --filter DiagnosticsIntegrationValidator
```

Then capture five fresh release processes. The `Production API` filter selects cached-key and varying-key cases that call `VerificationBatch` through `.cpu` and forced `.metal`; signing and fixture generation remain outside timing:

```bash
for run in 1 2 3 4 5; do
  swift run -c release OpalCryptoBenchmarks -- --suite metal --filter "Production API" --warmups 2 --samples 5 --output ".build/opalcrypto-benchmarks/production-metal-qualified-run-${run}.jsonl"
done
```

Every process must show, for both input shapes, at least 2x CPU/Metal end-to-end throughput at 8,192 records and Metal no slower than CPU at 4,096. The run also fails qualification on any CPU/Metal result mismatch, command failure, fallback during forced `.metal`, unbounded allocation, or regression against the retained benchmark kernel. All five July 11, 2026 production-path processes passed on macOS with the exact `Apple M1 Max` device name and Apple GPU family 7. That profile is qualified; all other profiles remain unqualified.

The exclusive `--validate-metal` run is still required for arithmetic, shader, and generated-corpus differential coverage. It complements rather than replaces the production-API gate. Neither gate authorizes a README claim or a general Apple Silicon performance claim; [metal-readiness.md](metal-readiness.md) records the narrow evidence and release decision.

## RPA And Metal Decision Gate

Do not start production Metal implementation from the Opal Crypto proxy benchmark alone. First measure an end-to-end Opal Base reusable payment address workload that consumes `OpalCrypto.Secp256k1.deriveSharedSecrets(privateKey:publicKeys:)` and reports candidate loading, public-key construction, batch shared-secret derivation, fingerprint or matching work, address or locking script derivation, wallet state, persistence, and indexer I/O separately.

Use that Opal Base benchmark to decide whether Opal Crypto shared-secret derivation is the dominant cost. If it is not dominant, prefer Opal Base batching, scan-window, persistence, or matching improvements before adding a GPU backend. If it is dominant at bulk historical restore scale, a Metal prototype may be justified as an optional Apple Silicon acceleration path for local historical catch-up, with the Swift CPU path remaining the portable fallback.

Any Metal path for receiver scanning is secret-bearing because it moves scan private-key scalar material into GPU work. It requires a separate security and product review covering buffer residency, command-buffer lifetime, memory clearing limits, debug capture exposure, device sharing, timing behavior, failure cleanup, and CPU fallback behavior before it can move beyond benchmark prototype status.
