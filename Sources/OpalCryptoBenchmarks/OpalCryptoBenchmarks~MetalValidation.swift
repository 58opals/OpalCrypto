// OpalCryptoBenchmarks~MetalValidation.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    enum MetalValidation {
        static func run() throws -> Int {
            let configuration = try MetalSchnorrVerificationCore.configuration()
            print("Metal validation configuration: \(configuration.description)")

            var checksum = try validateFieldOperations()
            checksum ^= try validateBitcoinCashSchnorrVectors()
            let generatedFixture = try makeGeneratedSchnorrFixture()
            checksum ^= try validateGeneratedSchnorrCorpus(generatedFixture)
            checksum ^= try validateWrongVerificationKey(generatedFixture)
            checksum ^= try validateVaryingVerificationKeys()
            return checksum
        }
    }
}
