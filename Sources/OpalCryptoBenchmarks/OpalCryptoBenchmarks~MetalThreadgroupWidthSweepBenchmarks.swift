// OpalCryptoBenchmarks~MetalThreadgroupWidthSweepBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func metalThreadgroupWidthSweepBenchmarkCases() -> [BenchmarkCase] {
        guard let configuration = try? MetalSchnorrVerificationCore.configuration() else {
            return []
        }
        return configuration.supportedThreadgroupWidths.map { threadgroupWidth in
            BenchmarkCase(
                name: "Metal Schnorr threadgroup \(threadgroupWidth) (cached key, 8192)",
                iterations: 1,
                suites: [.metal],
                operation: .sync { _ in
                    try MetalSchnorrVerificationCore.run(
                        batchInput: try preparedMetalSchnorrBatchInput(count: 8192),
                        threadgroupWidth: threadgroupWidth
                    )
                }
            )
        }
    }

}
