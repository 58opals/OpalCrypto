// OpalCryptoBenchmarks+BenchmarkCase.swift

extension OpalCryptoBenchmarks {
    struct BenchmarkCase {
        let name: String
        let iterations: Int
        let suites: [BenchmarkSuite]
        let operation: BenchmarkOperation

        func isIncluded(in suite: BenchmarkSuite) -> Bool {
            suite == .full || suites.contains(suite)
        }

        var usesMetalSchnorrVerificationCore: Bool {
            name.hasPrefix("Metal Schnorr verify core")
                || name.hasPrefix("Metal Schnorr verify end-to-end")
                || name.hasPrefix("Metal Schnorr verify warm")
                || name.hasPrefix("Metal Schnorr threadgroup")
        }
    }
}
