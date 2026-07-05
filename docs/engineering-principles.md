# Engineering Principles

Opal Crypto is a Swift-first BCH cryptography package. The implementation should stay readable, auditable, portable across the supported Apple platform set, and backed by correctness tests before performance claims are trusted.

## Implementation Boundary

- Keep the public contract facade-first through `OpalCrypto`.
- Keep the core cryptographic implementation in Swift.
- Do not add C or C++ cryptography engines, native shim backends, or vendored native acceleration libraries.
- Do not expose internal implementation models, file layout, benchmark helpers, or acceleration details as public API.
- Prefer small, explicit internal types over broad abstractions when working on hot cryptographic paths.

## Apple-Native Acceleration

Apple SDK frameworks are acceptable when they serve a clear package purpose and preserve the public facade contract.

Metal is an allowed exception to the Swift-only implementation preference when it is used as an Apple-native performance accelerator. A Metal path must remain optional, platform-gated, and benchmark-backed. The Swift CPU implementation remains the correctness source of truth and fallback.

Use Metal first for public, batched, independent workloads such as batch verification experiments. Public-key derivation remains an important CPU benchmark, but private-key derivation carries private scalar inputs and requires separate review before any GPU execution. Avoid moving private-key signing, secret scalar handling, or other secret-bearing operations to GPU execution unless a separate security review establishes the memory, timing, and side-channel invariants.

## Performance Policy

- Correctness validation comes before performance work.
- Treat benchmarks as same-machine evidence, not universal performance truth.
- Compare the same benchmark suite, filter, build configuration, toolchain, and machine class before claiming a speedup.
- Accept acceleration work only when end-to-end wall-clock results justify the added platform complexity.
- Keep performance improvements compatible with the supported public facade unless a public API change is explicitly designed and reviewed.

See [benchmarks.md](benchmarks.md) for the benchmark workflow, [performance-roadmap.md](performance-roadmap.md) for the staged CPU-to-Metal decision gate, and [metal-readiness.md](metal-readiness.md) for the current prototype boundary.
