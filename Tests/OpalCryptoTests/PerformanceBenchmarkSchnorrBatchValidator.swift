// PerformanceBenchmarkSchnorrBatchValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Performance benchmark Schnorr batch validation")
struct PerformanceBenchmarkSchnorrBatchValidator {
    @Test("Cached-key serial and parallel batches preserve ordered mixed results")
    func preserveCachedKeySerialAndParallelBatchOrdering() async throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(71).makeSigningKey()
        let sourceDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("cached-schnorr-\($0)")
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
        let expectedResults: [UInt32] = (0..<recordCount).map {
            $0.isMultiple(of: 3) ? 0 : 1
        }

        let serialResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
            signatures: signatures,
            digests: digests,
            verificationKey: signingKey.verificationKey
        )
        let parallelResults = try await PerformanceBenchmarkOperations.verifySchnorrBatchParallel(
            signatures: signatures,
            digests: digests,
            verificationKey: signingKey.verificationKey
        )

        #expect(serialResults == expectedResults)
        #expect(parallelResults == serialResults)
    }

    @Test("Varying-key serial and parallel batches preserve ordered mixed results")
    func preserveVaryingKeySerialAndParallelBatchOrdering() async throws {
        let signingKeys = try (0..<4).map {
            try OpalCryptoTestSupport.makeTypedPrivateKey(81 + $0).makeSigningKey()
        }
        let sourceDigests = try (0..<4).map {
            try OpalCryptoTestSupport.makeDigest("varying-schnorr-\($0)")
        }
        let sourceSignatures = try signingKeys.indices.map {
            try signingKeys[$0].signSchnorr(digest: sourceDigests[$0])
        }
        let sourceVerificationKeys = signingKeys.map(\.verificationKey)
        let recordCount = 256
        let signatures = (0..<recordCount).map { sourceSignatures[$0 % sourceSignatures.count] }
        let digests = (0..<recordCount).map { sourceDigests[$0 % sourceDigests.count] }
        let verificationKeys = (0..<recordCount).map { index in
            let sourceIndex = index % sourceVerificationKeys.count
            return index.isMultiple(of: 5)
                ? sourceVerificationKeys[(sourceIndex + 1) % sourceVerificationKeys.count]
                : sourceVerificationKeys[sourceIndex]
        }
        let expectedResults: [UInt32] = (0..<recordCount).map {
            $0.isMultiple(of: 5) ? 0 : 1
        }

        let serialResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
            signatures: signatures,
            digests: digests,
            verificationKeys: verificationKeys
        )
        let parallelResults = try await PerformanceBenchmarkOperations.verifySchnorrBatchParallel(
            signatures: signatures,
            digests: digests,
            verificationKeys: verificationKeys
        )
        let verificationKeyRawRepresentations = verificationKeys.map(\.rawRepresentation)
        let rawKeySerialResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
            signatures: signatures,
            digests: digests,
            verificationKeyRawRepresentations: verificationKeyRawRepresentations
        )
        let rawKeyParallelResults = try await PerformanceBenchmarkOperations
            .verifySchnorrBatchParallel(
                signatures: signatures,
                digests: digests,
                verificationKeyRawRepresentations: verificationKeyRawRepresentations
            )

        #expect(serialResults == expectedResults)
        #expect(parallelResults == serialResults)
        #expect(rawKeySerialResults == serialResults)
        #expect(rawKeyParallelResults == serialResults)
    }

    @Test("Cached and varying-key batches handle empty and single-record inputs")
    func handleEmptyAndSingleRecordInputs() async throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(91).makeSigningKey()
        let digest = try OpalCryptoTestSupport.makeDigest("single-schnorr")
        let signature = try signingKey.signSchnorr(digest: digest)
        let verificationKey = signingKey.verificationKey

        #expect(
            try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
                signatures: [],
                digests: [],
                verificationKey: verificationKey
            ).isEmpty
        )
        #expect(
            try await PerformanceBenchmarkOperations.verifySchnorrBatchParallel(
                signatures: [],
                digests: [],
                verificationKeys: []
            ).isEmpty
        )
        #expect(
            try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
                signatures: [signature],
                digests: [digest],
                verificationKeys: [verificationKey]
            ) == [1]
        )
        #expect(
            try await PerformanceBenchmarkOperations.verifySchnorrBatchParallel(
                signatures: [signature],
                digests: [digest],
                verificationKey: verificationKey
            ) == [1]
        )
        #expect(
            try await PerformanceBenchmarkOperations.verifySchnorrBatchParallel(
                signatures: [signature],
                digests: [digest],
                verificationKeyRawRepresentations: [verificationKey.rawRepresentation]
            ) == [1]
        )
    }

    @Test("Cached and varying-key batches reject mismatched input counts")
    func rejectMismatchedInputCounts() async throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(101).makeSigningKey()
        let digest = try OpalCryptoTestSupport.makeDigest("mismatched-schnorr")
        let cachedKeyError = PerformanceBenchmarkOperations.Error
            .mismatchedSchnorrBatchInputCounts(
                signatureCount: 0,
                digestCount: 1,
                verificationKeyCount: nil
            )
        let varyingKeyError = PerformanceBenchmarkOperations.Error
            .mismatchedSchnorrBatchInputCounts(
                signatureCount: 0,
                digestCount: 0,
                verificationKeyCount: 1
            )

        await expectInputCountMismatch(cachedKeyError) {
            _ = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
                signatures: [],
                digests: [digest],
                verificationKey: signingKey.verificationKey
            )
        }
        await expectInputCountMismatch(cachedKeyError) {
            _ = try await PerformanceBenchmarkOperations.verifySchnorrBatchParallel(
                signatures: [],
                digests: [digest],
                verificationKey: signingKey.verificationKey
            )
        }
        await expectInputCountMismatch(varyingKeyError) {
            _ = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
                signatures: [],
                digests: [],
                verificationKeys: [signingKey.verificationKey]
            )
        }
        await expectInputCountMismatch(varyingKeyError) {
            _ = try await PerformanceBenchmarkOperations.verifySchnorrBatchParallel(
                signatures: [],
                digests: [],
                verificationKeys: [signingKey.verificationKey]
            )
        }
        await expectInputCountMismatch(varyingKeyError) {
            _ = try await PerformanceBenchmarkOperations.verifySchnorrBatchParallel(
                signatures: [],
                digests: [],
                verificationKeyRawRepresentations: [
                    signingKey.verificationKey.rawRepresentation
                ]
            )
        }
    }

    private func expectInputCountMismatch(
        _ expectedError: PerformanceBenchmarkOperations.Error,
        operation: () async throws -> Void
    ) async {
        do {
            try await operation()
            Issue.record("Expected mismatched Schnorr batch input counts.")
        } catch let error as PerformanceBenchmarkOperations.Error {
            #expect(error == expectedError)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
