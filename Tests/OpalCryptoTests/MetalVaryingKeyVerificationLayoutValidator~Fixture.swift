// MetalVaryingKeyVerificationLayoutValidator~Fixture.swift

import Foundation
@testable import OpalCrypto

extension MetalVaryingKeyVerificationLayoutValidator {
    func makeFixture(recordCount: Int) throws -> (
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeys: [OpalCrypto.Signature.VerificationKey],
        expectedResults: [Bool]
    ) {
        let signingKeys = try (0..<4).map {
            try OpalCryptoTestSupport.makeTypedPrivateKey(111 + $0).makeSigningKey()
        }
        let sourceDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("metal-varying-key-\($0)")
        }
        let sourceSignatures = try signingKeys.indices.map {
            try signingKeys[$0].signSchnorr(digest: sourceDigests[$0])
        }
        let sourceVerificationKeys = signingKeys.map(\.verificationKey)
        let signatures = (0..<recordCount).map {
            sourceSignatures[$0 % sourceSignatures.count]
        }
        let digests = (0..<recordCount).map {
            sourceDigests[$0 % sourceDigests.count]
        }
        let verificationKeys = (0..<recordCount).map { index in
            let sourceIndex = index % sourceVerificationKeys.count
            return recordCount > 1 && index.isMultiple(of: 5)
                ? sourceVerificationKeys[(sourceIndex + 1) % sourceVerificationKeys.count]
                : sourceVerificationKeys[sourceIndex]
        }
        let expectedResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
            signatures: signatures,
            digests: digests,
            verificationKeys: verificationKeys
        ).map { $0 == 1 }

        return (signatures, digests, verificationKeys, expectedResults)
    }
}
