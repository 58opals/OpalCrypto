# Benchmark Workflow

Opal Crypto benchmarks are same-machine evidence for performance-sensitive cryptography work. Treat them as decision support after correctness passes, not as universal timing claims across hardware, OS versions, toolchains, or thermal states.

See [performance-roadmap.md](performance-roadmap.md) for the CPU-to-Metal staging model and [metal-readiness.md](metal-readiness.md) for the current Metal prototype gate.

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
- `hot`: secp256k1 public-key derivation, batch derivation, signature, cached-key, field/scalar arithmetic, and point multiplication benchmarks.
- `full`: every benchmark in the executable target.

## Output

The executable keeps human-readable stdout summaries and emits JSONL records. Each run starts with a `benchmark_run` metadata record, emits one `benchmark` record per executed benchmark, and ends with a `benchmark_summary` record containing the executed benchmark count and checksum.

When `--output` is provided, the same JSONL records are written to the requested path after creating parent directories. Keep generated artifacts under `.build/opalcrypto-benchmarks/` unless a task explicitly needs a different local path.

## Comparison Workflow

Use benchmarks as a before/after workflow on the same machine. Run a baseline from the target base branch, run the same suite and filter from the task branch, then compare benchmark names and median average time. A performance win is not valid if the correctness tests fail, benchmark filters differ, metadata shows a different toolchain or machine class, or the result only appears in one noisy sample.
