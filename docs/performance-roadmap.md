# Performance Roadmap

Opal Crypto performance work is CPU-first and benchmark-backed. Metal is allowed as an Apple-native acceleration option, but only after the Swift CPU path has plateaued on a specific public batched workload and only when end-to-end GPU execution beats the improved CPU implementation.

## Direction

- Keep the Swift implementation as the correctness source of truth and fallback.
- Keep Stages 1-4 free of public API changes.
- Do not add `Package.swift` dependencies for performance work.
- Do not add C or C++ backends.
- Do not move secret-bearing paths to GPU without a separate security and product review.
- Treat benchmark output as same-machine evidence, not universal performance truth.

## Stages

### Stage 1: Benchmark Workflow And First CPU Win

Finish the repeatable benchmark workflow, including suites, filters, metadata, JSONL output, and documentation. Pair that workflow with a narrow CPU batch-derivation improvement so future performance work has a trustworthy artifact trail.

Success bar: correctness tests pass, smoke JSONL output is captured, and at least one public batch derivation benchmark shows a targeted CPU win without API changes.

### Stage 2: CPU Batch Derivation Tuning

Continue on public batch derivation only: task sizing, allocation and copy reduction, scalar parsing flow, result assembly, and batch affine conversion.

Success bar: another targeted benchmark improvement of 10% or more without API changes.

### Stage 3: Cached Verification Tuning

Focus on cached verification hot paths: `ECDSA verify (cached key)`, `Schnorr verify (cached key)`, joint multiplication, verification-key cached tables, signature parsing, digest handling, and avoidable affine conversion work.

Success bar: 10% or more improvement in at least one cached verification benchmark with unchanged verification results.

### Stage 4: Field And Scalar Arithmetic Plateau Check

Optimize field or scalar arithmetic only when benchmark evidence points there. This stage is higher risk, so every accepted change needs exact vector or differential parity against the previous implementation.

Success bar: 10% or more improvement in a targeted field, scalar, or point-multiplication benchmark. CPU is considered plateaued only when two consecutive CPU-only stages fail to produce a 10% or better targeted win.

### Stage 5: Public-Verification Metal Performance Spike

After CPU plateau evidence, test Metal only on public batched work. The July 2026 spike established a fair multicore Swift baseline, optimized cached-key Schnorr verification, and then added varying-key tables only after the cached-key gate passed. Its benchmark core became the evidence base for the separately packaged production path in Stage 5B.

Success bar: in each of five fresh release processes with two warmups and five samples, Metal must deliver at least 2x end-to-end throughput at 8,192 records and must be no slower than multicore Swift at 4,096. For varying keys, both end-to-end sides begin with raw public-key bytes and include parsing and table construction. Metal timing additionally includes packing, uploads, command scheduling, synchronization, readback, and parity validation. Kernel-only timing is not enough.

Status: passed on the recorded M1 Max for both cached and varying public keys. The measured crossover is greater than 1,024 and no higher than 4,096. This authorizes continued benchmark and product-fit investigation, not production routing or general marketing.

See [metal-readiness.md](metal-readiness.md) for the current readiness decision, qualified profile, and acceptance evidence.

### Stage 5B: Production Schnorr Batch Qualification

Promote the proven public-data workload behind an explicit `OpalCrypto.Signature.Schnorr.VerificationBatch` boundary. The public API supports one cached verification key or one public key per record, preserves result order, and exposes `.automatic`, `.cpu`, and `.metal` execution policies. The optimized multicore Swift backend is independently production-capable and remains the correctness source and portable fallback.

The packaged Metal implementation is qualified for one narrow initial profile: macOS, exact device name `Apple M1 Max`, and Apple GPU family 7. Warm automatic selection starts at 4,096 records; a cold path that has not initialized and self-tested its pipeline starts at 8,192. Unqualified profiles, Low Power Mode, and serious or critical thermal state select CPU. Forced Metal has no CPU fallback. Automatic recovery discards all Metal output and recomputes the entire batch on CPU; cancellation never falls back.

Success bar: focused API, CPU parity, cancellation, diagnostics, resource-loading, failure-injection, and fallback tests pass; then each of five fresh release processes must reproduce the 2x-at-8,192 and no-slower-at-4,096 gate for both cached and varying inputs through the public production API. Production diagnostics must remain aggregate and public-safe, resource and allocation limits must be bounded, and every returned result must match Swift.

Status: passed on July 11, 2026 for the exact recorded M1 Max profile. Five fresh final-runtime production-API processes passed both input-shape gates: cached-key speedup was 2.43x–2.97x and varying-key speedup was 3.86x–4.73x at 8,192 records, while Metal beat CPU at 4,096 in every process. Automatic Metal selection is enabled only for that profile. This stage does not authorize a README or general Apple Silicon performance claim.

### Stage 6: RPA-Shaped Benchmark Gate

Before any receiver-scan Metal work, measure the real reusable payment address workload in Opal Base. The Opal Crypto benchmark target may keep a generic shared-secret and fingerprint proxy, but it must not encode scan-window policy, address derivation, transaction output matching, wallet state, persistence, or indexer behavior.

Success bar: Opal Base reports an end-to-end local scan benchmark with stage timings and shows that Opal Crypto shared-secret derivation remains the dominant cost at bulk historical restore scale after ordinary CPU batching and pipeline improvements. If that bar is not met, continue CPU and pipeline tuning before starting a secret-bearing Metal path.

### Stage 7: Apple Silicon Bulk Historical Scan Prototype

If Stage 6 proves a persistent Opal Crypto bottleneck, prototype a platform-gated Metal backend for Apple Silicon bulk historical receiver scanning. Position the feature as optional local acceleration for historical catch-up, not as an Apple-only requirement: the Swift CPU implementation remains the correctness source of truth and portable fallback.

Success bar: the prototype beats the improved CPU path end-to-end on the Opal Base RPA-shaped workload, preserves exact results against the CPU path, and passes a separate secret-handling review for GPU buffer residency, command-buffer lifetime, debug capture exposure, failure cleanup, and fallback behavior.

## Required Validation

Each stage must run:

```bash
swift build -c release
swift test
```

When batch, arithmetic, or verification internals change, also run:

```bash
OPALCRYPTO_RUN_PERF_TESTS=1 swift test
```

Metal verification work must additionally run the exclusive differential validator and the focused release suite:

```bash
swift run -c release OpalCryptoBenchmarks -- --validate-metal
swift run -c release OpalCryptoBenchmarks -- --suite metal --warmups 2 --samples 5
```

Production Schnorr batch work must run the focused API and aggregate-diagnostics validators:

```bash
swift test --filter PublicAPISchnorrBatchVerificationValidator
swift test --filter SchnorrBatchVerificationOperationValidator
swift test --filter DiagnosticsIntegrationValidator
```

To qualify or requalify an automatic Metal profile, capture five fresh processes through the public API:

```bash
for run in 1 2 3 4 5; do
  swift run -c release OpalCryptoBenchmarks -- --suite metal --filter "Production API" --warmups 2 --samples 5 --output ".build/opalcrypto-benchmarks/production-metal-qualified-run-${run}.jsonl"
done
```

Each stage should capture focused before/after JSONL artifacts under `.build/opalcrypto-benchmarks/` and a smoke artifact:

```bash
swift run -c release OpalCryptoBenchmarks -- --suite smoke --output .build/opalcrypto-benchmarks/<stage>-smoke.jsonl
```

## Metal Gates

Benchmark-only Metal work starts only when all of the following are true:

- The CPU implementation has two consecutive CPU-only stages below the 10% targeted improvement bar.
- A specific public batched benchmark remains expensive after accepted CPU work.
- For receiver scanning, an Opal Base reusable payment address benchmark shows that Opal Crypto shared-secret derivation dominates bulk historical restore cost.
- The GPU candidate has a clear end-to-end acceptance target against the improved Swift CPU path.
- The workload is public data or has passed a separate review for secret-handling risk.
- The Swift CPU path remains the default fallback.

Passing a benchmark spike does not authorize automatic production routing. The public CPU batch API may proceed independently. A Metal profile additionally needs production-API parity and failure tests, precompiled resource validation, bounded error and fallback behavior, and the five-process production-path gate. Certification beyond the initial exact M1 Max profile still requires a real caller in the profitable batch range, measurements across each intended Apple Silicon device class, all supported-platform validation, and explicit API, security, and product review.

## Phase Closeout

The first optimization phase is complete. The accepted work adds a repeatable benchmark workflow, JSONL artifacts, benchmark suites and filters, a smoke workflow, documentation, and CPU-only wins in batch public-key derivation and cached verification. The accepted CPU changes stay internal, keep public APIs stable, avoid dependency changes, and keep the Swift implementation as the correctness source of truth.

Stage 1 and Stage 2 produced benchmark-backed public batch derivation improvements through task sizing. Stage 3 produced a cached ECDSA verification win by avoiding repeated signature parsing, avoiding unnecessary compressed-key materialization in diagnostics, using X-only affine conversion for ECDSA verification, and widening the WNAF precomputed tables used by generator and cached-key multiplication. Stage 4 arithmetic and Stage 4B public-batch allocation experiments did not meet the 10% bar and were reverted.

Stage 5 progressed from a command/readback probe to a real public-data secp256k1 Schnorr kernel. The July 11, 2026 spike added ordered serial and multicore CPU baselines, bounded reusable buffers, optimized field arithmetic, coalesced `Int8` WNAF digits, immutable cached tables, and width-3 varying-key structure-of-arrays tables with batched affine conversion. All five cached-key and all five corrected raw-key varying-key evidence processes passed the 2x-at-8,192 and no-slower-at-4,096 gate on the recorded M1 Max.

The benchmark phase and the exact M1 Max production qualification therefore close as a performance **go**. Stage 5B delivers an ordered public Schnorr batch API, optimized Swift CPU execution, a precompiled Metal resource, a bounded runtime, and aggregate diagnostics. Swift remains the correctness source and portable fallback. Other device profiles, cross-device claims, and general marketing remain a **no-go**. See [metal-readiness.md](metal-readiness.md) for exact commands, hardware/toolchain metadata, before/after and per-process results, profiler captures, crossover, and the qualification boundary.
