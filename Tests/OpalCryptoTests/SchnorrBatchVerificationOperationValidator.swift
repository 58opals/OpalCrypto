// SchnorrBatchVerificationOperationValidator.swift

import Testing
@testable import OpalCrypto

@Suite("Schnorr batch verification operation")
struct SchnorrBatchVerificationOperationValidator {
    @Test("Serial and parallel cached-key CPU execution have exact parity")
    func preserveCachedKeySerialAndParallelCPUParity() async throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(361).makeSigningKey()
        let sourceDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("operation-cached-batch-\($0)")
        }
        let sourceSignatures = try sourceDigests.map {
            try signingKey.signSchnorr(digest: $0)
        }
        let recordCount = 256
        let input = SchnorrBatchVerificationInput(
            signatures: (0..<recordCount).map { sourceSignatures[$0 % sourceSignatures.count] },
            digests: (0..<recordCount).map { index in
                let sourceIndex = index % sourceDigests.count
                return index.isMultiple(of: 7)
                    ? sourceDigests[(sourceIndex + 1) % sourceDigests.count]
                    : sourceDigests[sourceIndex]
            },
            verificationKey: signingKey.verificationKey
        )

        let serialResults = try SchnorrBatchVerificationOperation.verifySerialUsingCPU(input: input)
        let parallelResults = try await SchnorrBatchVerificationOperation.verifyUsingCPU(input: input)

        #expect(parallelResults == serialResults)
        #expect(serialResults == (0..<recordCount).map { !$0.isMultiple(of: 7) })
    }

    @Test("Serial and parallel varying-key CPU execution have exact parity")
    func preserveVaryingKeySerialAndParallelCPUParity() async throws {
        let signingKeys = try (0..<4).map {
            try OpalCryptoTestSupport.makeTypedPrivateKey(371 + $0).makeSigningKey()
        }
        let sourceDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("operation-varying-batch-\($0)")
        }
        let sourceSignatures = try signingKeys.indices.map {
            try signingKeys[$0].signSchnorr(digest: sourceDigests[$0])
        }
        let sourcePublicKeys = signingKeys.map(\.publicKey)
        let recordCount = 256
        let input = SchnorrBatchVerificationInput(
            signatures: (0..<recordCount).map { sourceSignatures[$0 % sourceSignatures.count] },
            digests: (0..<recordCount).map { sourceDigests[$0 % sourceDigests.count] },
            publicKeys: (0..<recordCount).map { index in
                let sourceIndex = index % sourcePublicKeys.count
                return index.isMultiple(of: 11)
                    ? sourcePublicKeys[(sourceIndex + 1) % sourcePublicKeys.count]
                    : sourcePublicKeys[sourceIndex]
            }
        )

        let serialResults = try SchnorrBatchVerificationOperation.verifySerialUsingCPU(input: input)
        let parallelResults = try await SchnorrBatchVerificationOperation.verifyUsingCPU(input: input)

        #expect(parallelResults == serialResults)
        #expect(serialResults == (0..<recordCount).map { !$0.isMultiple(of: 11) })
    }

    @Test("Uniform varying keys normalize to one prepared verification key")
    func normalizeUniformVaryingKeysToOnePreparedVerificationKey() async throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(401).makeSigningKey()
        let otherSigningKey = try OpalCryptoTestSupport.makeTypedPrivateKey(402).makeSigningKey()
        let digest = try OpalCryptoTestSupport.makeDigest("operation-uniform-key-batch")
        let signature = try signingKey.signSchnorr(digest: digest)
        let uniformPublicKeys = Array(repeating: signingKey.publicKey, count: 256)
        let varyingInput = SchnorrBatchVerificationInput(
            signatures: Array(repeating: signature, count: 256),
            digests: Array(repeating: digest, count: 256),
            publicKeys: uniformPublicKeys
        )
        let cachedInput = SchnorrBatchVerificationInput(
            signatures: varyingInput.signatures,
            digests: varyingInput.digests,
            verificationKey: signingKey.verificationKey
        )

        #expect(
            SchnorrBatchVerificationOperation.makeUniformVerificationKeyModel(
                publicKeys: uniformPublicKeys
            ) != nil
        )
        #expect(
            SchnorrBatchVerificationOperation.makeUniformVerificationKeyModel(
                publicKeys: [signingKey.publicKey, otherSigningKey.publicKey]
            ) == nil
        )
        let varyingResults = try await SchnorrBatchVerificationOperation.verifyUsingCPU(
            input: varyingInput
        )
        let cachedResults = try await SchnorrBatchVerificationOperation.verifyUsingCPU(
            input: cachedInput
        )

        #expect(varyingResults == cachedResults)
        #expect(varyingResults == Array(repeating: true, count: 256))
    }
}
