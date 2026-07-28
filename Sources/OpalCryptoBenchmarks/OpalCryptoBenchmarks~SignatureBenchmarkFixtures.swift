// OpalCryptoBenchmarks~SignatureBenchmarkFixtures.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    private static let schnorrDistinctBatchFixtureResult:
        Result<SchnorrDistinctBatchFixture, Swift.Error> = Result {
            try SchnorrDistinctBatchFixture()
        }
    private static let schnorrVaryingKeyBatchFixtureResult:
        Result<SchnorrVaryingKeyBatchFixture, Swift.Error> = Result {
            try SchnorrVaryingKeyBatchFixture()
        }

    static var schnorrDistinctBatchFixture: SchnorrDistinctBatchFixture {
        get throws {
            try schnorrDistinctBatchFixtureResult.get()
        }
    }

    static var schnorrVaryingKeyBatchFixture: SchnorrVaryingKeyBatchFixture {
        get throws {
            try schnorrVaryingKeyBatchFixtureResult.get()
        }
    }

    static func cpuSchnorrBatchFixture(
        count: Int
    ) throws -> SchnorrCPUVerificationBatchFixture {
        guard let fixture = try schnorrDistinctBatchFixture.cpuBatches[count] else {
            throw MetalVerificationProbeError.invalidResult(index: count)
        }
        return fixture
    }
}
