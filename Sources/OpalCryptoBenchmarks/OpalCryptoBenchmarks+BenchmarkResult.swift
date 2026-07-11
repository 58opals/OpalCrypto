// OpalCryptoBenchmarks+BenchmarkResult.swift

extension OpalCryptoBenchmarks {
    struct BenchmarkResult {
        let name: String
        let iterations: Int
        let sampleCount: Int
        let samplesNanoseconds: [UInt64]
        let medianMilliseconds: Double
        let minimumMilliseconds: Double
        let medianAverageMicroseconds: Double
        let metalStageSamples: [MetalSchnorrVerificationCore.StageMeasurement]

        var jsonObject: [String: Any] {
            var object: [String: Any] = [
                "type": "benchmark",
                "name": name,
                "iterations": iterations,
                "sample_count": sampleCount,
                "samples_ns": samplesNanoseconds.map(Int64.init),
                "median_ms": medianMilliseconds,
                "min_ms": minimumMilliseconds,
                "median_avg_us": medianAverageMicroseconds
            ]
            if !metalStageSamples.isEmpty {
                object["metal_stage_samples"] = metalStageSamples.map(\.jsonObject)
            }
            return object
        }
    }
}
