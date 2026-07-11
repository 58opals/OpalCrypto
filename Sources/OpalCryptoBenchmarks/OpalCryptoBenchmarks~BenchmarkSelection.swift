// OpalCryptoBenchmarks~BenchmarkSelection.swift

extension OpalCryptoBenchmarks {
    static func benchmarkCases() -> [BenchmarkCase] {
        publicKeyBenchmarks()
            + sharedSecretBenchmarks()
            + signatureBenchmarks()
            + keyDerivationBenchmarks()
            + encodingBenchmarks()
    }

    static func selectedBenchmarks(options: BenchmarkOptions) throws -> [BenchmarkCase] {
        var availableBenchmarks = benchmarkCases()
        if options.suite == .metal || options.suite == .full {
            let candidateSweepNames = [64, 128, 256, 512].map {
                "Metal Schnorr threadgroup \($0) (cached key, 8192)"
            }
            if candidateSweepNames.contains(where: options.filterMatches) {
                availableBenchmarks += metalThreadgroupWidthSweepBenchmarkCases()
            }
        }
        let selected = availableBenchmarks.filter { benchmark in
            benchmark.isIncluded(in: options.suite)
                && options.filterMatches(name: benchmark.name)
        }
        guard !selected.isEmpty else {
            throw BenchmarkCommandError.noMatchingBenchmarks
        }
        return selected
    }
}
