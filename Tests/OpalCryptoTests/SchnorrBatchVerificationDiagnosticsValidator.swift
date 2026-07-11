// SchnorrBatchVerificationDiagnosticsValidator.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

@Suite("Schnorr batch verification diagnostics", .serialized)
struct SchnorrBatchVerificationDiagnosticsValidator {
    @Test("CPU batch verification records one aggregate success sequence")
    func recordAggregateCPUSuccessSequence() async throws {
        try await OpalDiagnostics.withConfiguration(
            DiagnosticsIntegrationValidator.diagnosticsConfiguration
        ) {
            let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(381).makeSigningKey()
            let validDigest = try OpalCryptoTestSupport.makeDigest("diagnostics-valid-batch")
            let invalidDigest = try OpalCryptoTestSupport.makeDigest("diagnostics-invalid-batch")
            let signature = try signingKey.signSchnorr(digest: validDigest)
            let batch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
                signatures: [signature, signature],
                digests: [validDigest, invalidDigest],
                publicKeys: [signingKey.publicKey, signingKey.publicKey]
            )
            OpalDiagnostics.clearRecentRecords()

            let results = try await batch.verify(using: .cpu)

            #expect(results == [true, false])
            let beginRecord = try #require(
                OpalDiagnostics.recentRecords(
                    matching: .init(event: .schnorrBatchVerifyBegin)
                ).first
            )
            let successRecord = try #require(
                OpalDiagnostics.recentRecords(
                    matching: .init(event: .schnorrBatchVerifySucceeded)
                ).first
            )
            #expect(beginRecord.category == .signature)
            #expect(successRecord.category == .signature)
            #expect(findField(named: "requested_policy", in: successRecord)?.value == "cpu")
            #expect(findField(named: "selected_backend", in: successRecord)?.value == "cpu")
            #expect(findField(named: "input_shape", in: successRecord)?.value == "varying_keys")
            #expect(findField(named: "record_count", in: successRecord)?.value == "2")
            #expect(findField(named: "chunk_count", in: successRecord)?.value == "1")
            #expect(findField(named: "valid_result_count", in: successRecord)?.value == "1")
            #expect(findField(named: "invalid_result_count", in: successRecord)?.value == "1")
            #expect(findField(named: "total_duration", in: successRecord) != nil)
            #expect(findField(named: "signature", in: successRecord) == nil)
            #expect(findField(named: "digest", in: successRecord) == nil)
            #expect(findField(named: "public_key", in: successRecord) == nil)
            #expect(
                OpalDiagnostics.recentRecords(
                    matching: .init(event: .schnorrBatchVerifyFailed)
                ).isEmpty
            )
            #expect(
                OpalDiagnostics.recentRecords(
                    matching: .init(event: .schnorrBatchVerifyFallback)
                ).isEmpty
            )
        }
    }

    @Test("Cancellation does not record batch failure or fallback events")
    func omitFailureAndFallbackEventsForCancellation() async throws {
        try await OpalDiagnostics.withConfiguration(
            DiagnosticsIntegrationValidator.diagnosticsConfiguration
        ) {
            let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(391).makeSigningKey()
            let digest = try OpalCryptoTestSupport.makeDigest("diagnostics-cancelled-batch")
            let signature = try signingKey.signSchnorr(digest: digest)
            let batch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
                signatures: Array(repeating: signature, count: 256),
                digests: Array(repeating: digest, count: 256),
                verificationKey: signingKey.verificationKey
            )
            OpalDiagnostics.clearRecentRecords()
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

            #expect(
                OpalDiagnostics.recentRecords(
                    matching: .init(event: .schnorrBatchVerifyFailed)
                ).isEmpty
            )
            #expect(
                OpalDiagnostics.recentRecords(
                    matching: .init(event: .schnorrBatchVerifyFallback)
                ).isEmpty
            )
        }
    }

    private func findField(
        named name: String,
        in record: OpalDiagnostics.Record
    ) -> OpalDiagnostics.Field? {
        record.fields.first { $0.name == name }
    }
}
