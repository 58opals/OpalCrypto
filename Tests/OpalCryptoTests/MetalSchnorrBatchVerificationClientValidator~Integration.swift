// MetalSchnorrBatchVerificationClientValidator~Integration.swift

import Testing
@testable import OpalCrypto

extension MetalSchnorrBatchVerificationClientValidator {
    @Test(
        "Concurrent cached and varying Metal verification has no cross-talk",
        .enabled(if: MetalSchnorrBatchVerificationClient.isCertifiedDeviceAvailable)
    )
    func preventCrossTalkBetweenConcurrentCachedAndVaryingVerification() async throws {
        let cachedSigningKey = try OpalCryptoTestSupport
            .makeTypedPrivateKey(421)
            .makeSigningKey()
        let cachedSourceDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("metal-cached-concurrent-\($0)")
        }
        let cachedSourceSignatures = try cachedSourceDigests.map {
            try cachedSigningKey.signSchnorr(digest: $0)
        }
        let recordCount = 64
        let cachedSignatures = (0..<recordCount).map {
            cachedSourceSignatures[$0 % cachedSourceSignatures.count]
        }
        let cachedDigests = (0..<recordCount).map { index in
            let sourceIndex = index % cachedSourceDigests.count
            return index.isMultiple(of: 3)
                ? cachedSourceDigests[(sourceIndex + 1) % cachedSourceDigests.count]
                : cachedSourceDigests[sourceIndex]
        }
        let cachedBatch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: cachedSignatures,
            digests: cachedDigests,
            verificationKey: cachedSigningKey.verificationKey
        )

        let varyingSigningKeys = try (0..<4).map {
            try OpalCryptoTestSupport.makeTypedPrivateKey(431 + $0).makeSigningKey()
        }
        let varyingDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("metal-varying-concurrent-\($0)")
        }
        let varyingSourceSignatures = try varyingSigningKeys.indices.map {
            try varyingSigningKeys[$0].signSchnorr(digest: varyingDigests[$0])
        }
        let varyingSourcePublicKeys = varyingSigningKeys.map(\.publicKey)
        let varyingBatch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: (0..<recordCount).map {
                varyingSourceSignatures[$0 % varyingSourceSignatures.count]
            },
            digests: (0..<recordCount).map {
                varyingDigests[$0 % varyingDigests.count]
            },
            publicKeys: (0..<recordCount).map { index in
                let sourceIndex = index % varyingSourcePublicKeys.count
                return index.isMultiple(of: 5)
                    ? varyingSourcePublicKeys[
                        (sourceIndex + 1) % varyingSourcePublicKeys.count
                    ]
                    : varyingSourcePublicKeys[sourceIndex]
            }
        )

        async let cachedResults = cachedBatch.verify(using: .metal)
        async let varyingResults = varyingBatch.verify(using: .metal)
        let results = try await (cachedResults, varyingResults)

        #expect(results.0 == (0..<recordCount).map { !$0.isMultiple(of: 3) })
        #expect(results.1 == (0..<recordCount).map { !$0.isMultiple(of: 5) })
    }
}
