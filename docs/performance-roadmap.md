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

### Stage 5: Metal Readiness And Prototype Plan

Start Metal only after CPU plateau evidence exists and a public batched workload remains expensive. First candidate selection must respect the secret-bearing GPU boundary: public batch verification is eligible by default, while private-key public-key derivation needs separate review before GPU execution.

Success bar: the Metal prototype must beat the improved Swift CPU path end-to-end, including buffer setup, command scheduling, synchronization, and readback. Kernel-only timing is not enough.

See [metal-readiness.md](metal-readiness.md) for the current readiness decision, candidate selection, and prototype acceptance bar.

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

Each stage should capture focused before/after JSONL artifacts under `.build/opalcrypto-benchmarks/` and a smoke artifact:

```bash
swift run -c release OpalCryptoBenchmarks -- --suite smoke --output .build/opalcrypto-benchmarks/<stage>-smoke.jsonl
```

## Metal Gate

Metal starts only when all of the following are true:

- The CPU implementation has two consecutive CPU-only stages below the 10% targeted improvement bar.
- A specific public batched benchmark remains expensive after accepted CPU work.
- The GPU candidate has a clear end-to-end acceptance target against the improved Swift CPU path.
- The workload is public data or has passed a separate review for secret-handling risk.
- The Swift CPU path remains the default fallback.

## Phase Closeout

The first optimization phase is complete. The accepted work adds a repeatable benchmark workflow, JSONL artifacts, benchmark suites and filters, a smoke workflow, documentation, and CPU-only wins in batch public-key derivation and cached verification. The accepted CPU changes stay internal, keep public APIs stable, avoid dependency changes, and keep the Swift implementation as the correctness source of truth.

Stage 1 and Stage 2 produced benchmark-backed public batch derivation improvements through task sizing. Stage 3 produced a cached ECDSA verification win by avoiding repeated signature parsing, avoiding unnecessary compressed-key materialization in diagnostics, using X-only affine conversion for ECDSA verification, and widening the WNAF precomputed tables used by generator and cached-key multiplication. Stage 4 arithmetic and Stage 4B public-batch allocation experiments did not meet the 10% bar and were reverted.

Stage 5 added benchmark-only public-data batch verification baselines and a Metal command/readback probe. The probe did not execute secp256k1 verification on GPU and did not demonstrate the required 10% end-to-end win across two release runs, so Metal remains a no-go for production paths in this phase. See [metal-readiness.md](metal-readiness.md) for the captured artifacts, timing deltas, and future acceptance bar.
