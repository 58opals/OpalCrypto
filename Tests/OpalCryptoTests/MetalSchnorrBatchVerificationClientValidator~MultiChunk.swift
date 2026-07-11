// MetalSchnorrBatchVerificationClientValidator~MultiChunk.swift

import Testing
@testable import OpalCrypto

extension MetalSchnorrBatchVerificationClientValidator {
    @Test("Production Metal preserves order across multiple chunks")
    func preserveOrderAcrossMultipleProductionMetalChunks() async throws {
        guard MetalSchnorrBatchVerificationClient.isCertifiedDeviceAvailable else {
            return
        }

        let recordCount = 8_193
        let cachedSigningKey = try OpalCryptoTestSupport
            .makeTypedPrivateKey(451)
            .makeSigningKey()
        let cachedSourceDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("metal-cached-multichunk-\($0)")
        }
        let cachedSourceSignatures = try cachedSourceDigests.map {
            try cachedSigningKey.signSchnorr(digest: $0)
        }
        let cachedBatch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: (0..<recordCount).map {
                cachedSourceSignatures[$0 % cachedSourceSignatures.count]
            },
            digests: (0..<recordCount).map { index in
                let sourceIndex = index % cachedSourceDigests.count
                return index.isMultiple(of: 5)
                    ? cachedSourceDigests[(sourceIndex + 1) % cachedSourceDigests.count]
                    : cachedSourceDigests[sourceIndex]
            },
            verificationKey: cachedSigningKey.verificationKey
        )

        let varyingSigningKeys = try (0..<4).map {
            try OpalCryptoTestSupport.makeTypedPrivateKey(461 + $0).makeSigningKey()
        }
        let varyingDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("metal-varying-multichunk-\($0)")
        }
        let varyingSignatures = try varyingSigningKeys.indices.map {
            try varyingSigningKeys[$0].signSchnorr(digest: varyingDigests[$0])
        }
        let varyingPublicKeys = varyingSigningKeys.map(\.publicKey)
        let varyingBatch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: (0..<recordCount).map {
                varyingSignatures[$0 % varyingSignatures.count]
            },
            digests: (0..<recordCount).map {
                varyingDigests[$0 % varyingDigests.count]
            },
            publicKeys: (0..<recordCount).map { index in
                let sourceIndex = index % varyingPublicKeys.count
                return index.isMultiple(of: 7)
                    ? varyingPublicKeys[(sourceIndex + 1) % varyingPublicKeys.count]
                    : varyingPublicKeys[sourceIndex]
            }
        )

        let cachedResults = try await cachedBatch.verify(using: .metal)
        let varyingResults = try await varyingBatch.verify(using: .metal)

        #expect(cachedResults == (0..<recordCount).map { !$0.isMultiple(of: 5) })
        #expect(varyingResults == (0..<recordCount).map { !$0.isMultiple(of: 7) })
    }
}
