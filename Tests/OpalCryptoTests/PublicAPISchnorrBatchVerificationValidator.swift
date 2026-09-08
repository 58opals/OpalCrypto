// PublicAPISchnorrBatchVerificationValidator.swift

import Foundation
import OpalCrypto
import Testing

@Suite("Public API Schnorr batch verification")
struct PublicAPISchnorrBatchVerificationValidator {
    @Test("Cached-key verification preserves ordered mixed results")
    func preserveCachedKeyVerificationOrdering() async throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(301).makeSigningKey()
        let sourceDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("public-cached-batch-\($0)")
        }
        let sourceSignatures = try sourceDigests.map {
            try signingKey.signSchnorr(digest: $0)
        }
        let recordCount = 256
        let signatures = (0..<recordCount).map { sourceSignatures[$0 % sourceSignatures.count] }
        let digests = (0..<recordCount).map { index in
            let sourceIndex = index % sourceDigests.count
            return index.isMultiple(of: 3)
                ? sourceDigests[(sourceIndex + 1) % sourceDigests.count]
                : sourceDigests[sourceIndex]
        }
        let batch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: signatures,
            digests: digests,
            verificationKey: signingKey.verificationKey
        )
        let expected = (0..<recordCount).map { !$0.isMultiple(of: 3) }
        let cpuResults = try await batch.verify(using: .cpu)
        let automaticResults = try await batch.verify()

        #expect(batch.count == recordCount)
        #expect(!batch.isEmpty)
        #expect(cpuResults == expected)
        #expect(automaticResults == expected)
    }

    @Test("Varying-key verification preserves ordered mixed results")
    func preserveVaryingKeyVerificationOrdering() async throws {
        let signingKeys = try (0..<4).map {
            try OpalCryptoTestSupport.makeTypedPrivateKey(311 + $0).makeSigningKey()
        }
        let sourceDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("public-varying-batch-\($0)")
        }
        let sourceSignatures = try signingKeys.indices.map {
            try signingKeys[$0].signSchnorr(digest: sourceDigests[$0])
        }
        let sourcePublicKeys = signingKeys.map(\.publicKey)
        let recordCount = 256
        let signatures = (0..<recordCount).map { sourceSignatures[$0 % sourceSignatures.count] }
        let digests = (0..<recordCount).map { sourceDigests[$0 % sourceDigests.count] }
        let publicKeys = (0..<recordCount).map { index in
            let sourceIndex = index % sourcePublicKeys.count
            return index.isMultiple(of: 5)
                ? sourcePublicKeys[(sourceIndex + 1) % sourcePublicKeys.count]
                : sourcePublicKeys[sourceIndex]
        }
        let batch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: signatures,
            digests: digests,
            publicKeys: publicKeys
        )
        let results = try await batch.verify(using: .cpu)

        #expect(results == (0..<recordCount).map { !$0.isMultiple(of: 5) })
    }

    @Test("Empty and single-record batches return one result per record")
    func returnOneResultPerRecordForEmptyAndSingleBatches() async throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(321).makeSigningKey()
        let digest = try OpalCryptoTestSupport.makeDigest("public-single-batch")
        let signature = try signingKey.signSchnorr(digest: digest)
        let emptyCachedBatch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: [],
            digests: [],
            verificationKey: signingKey.verificationKey
        )
        let emptyVaryingBatch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: [],
            digests: [],
            publicKeys: []
        )
        let singleBatch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: [signature],
            digests: [digest],
            publicKeys: [signingKey.publicKey]
        )
        let emptyCachedResults = try await emptyCachedBatch.verify(using: .cpu)
        let emptyVaryingResults = try await emptyVaryingBatch.verify(using: .metal)
        let singleResults = try await singleBatch.verify(using: .cpu)

        #expect(emptyCachedBatch.count == 0)
        #expect(emptyCachedBatch.isEmpty)
        #expect(emptyCachedResults.isEmpty)
        #expect(emptyVaryingResults.isEmpty)
        #expect(singleResults == [true])
    }

    @Test("Forced Metal verifies cached and varying public-key batches when certified")
    func verifyCachedAndVaryingBatchesUsingForcedMetalWhenCertified() async throws {
        let signingKeys = try (0..<2).map {
            try OpalCryptoTestSupport.makeTypedPrivateKey(325 + $0).makeSigningKey()
        }
        let digests = try (0..<2).map {
            try OpalCryptoTestSupport.makeDigest("public-forced-metal-batch-\($0)")
        }
        let signatures = try signingKeys.indices.map {
            try signingKeys[$0].signSchnorr(digest: digests[$0])
        }
        let cachedBatch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: [signatures[0], signatures[0]],
            digests: [digests[0], digests[0]],
            verificationKey: signingKeys[0].verificationKey
        )
        let varyingBatch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: signatures,
            digests: digests,
            publicKeys: signingKeys.map(\.publicKey)
        )

        do {
            let cachedResults = try await cachedBatch.verify(using: .metal)
            let varyingResults = try await varyingBatch.verify(using: .metal)
            #expect(cachedResults == [true, true])
            #expect(varyingResults == [true, true])
        } catch let error as OpalCrypto.Signature.Schnorr.VerificationBatch.Error {
            #expect(error == .executionUnavailable(policy: .metal))
        }
    }

    @Test("CPU verification propagates task cancellation")
    func propagateCPUVerificationCancellation() async throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(331).makeSigningKey()
        let digest = try OpalCryptoTestSupport.makeDigest("public-cancelled-batch")
        let signature = try signingKey.signSchnorr(digest: digest)
        let batch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
            signatures: Array(repeating: signature, count: 256),
            digests: Array(repeating: digest, count: 256),
            verificationKey: signingKey.verificationKey
        )
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await batch.verify(using: .cpu)
        }

        do {
            _ = try await task.value
            Issue.record("Expected batch verification cancellation.")
        } catch is CancellationError {
            // Expected.
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
