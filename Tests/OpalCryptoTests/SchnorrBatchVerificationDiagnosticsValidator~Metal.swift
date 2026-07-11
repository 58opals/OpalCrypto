// SchnorrBatchVerificationDiagnosticsValidator~Metal.swift

import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension SchnorrBatchVerificationDiagnosticsValidator {
    @Test("Metal batch verification records aggregate stage durations")
    func recordAggregateMetalStageDurations() async throws {
        guard MetalSchnorrBatchVerificationClient.isCertifiedDeviceAvailable else {
            return
        }
        try await OpalDiagnostics.withConfiguration(
            DiagnosticsIntegrationValidator.diagnosticsConfiguration
        ) {
            let signingKey = try OpalCryptoTestSupport
                .makeTypedPrivateKey(401)
                .makeSigningKey()
            let digest = try OpalCryptoTestSupport.makeDigest(
                "diagnostics-metal-batch"
            )
            let signature = try signingKey.signSchnorr(digest: digest)
            let batch = try OpalCrypto.Signature.Schnorr.VerificationBatch(
                signatures: [signature, signature],
                digests: [digest, digest],
                verificationKey: signingKey.verificationKey
            )
            OpalDiagnostics.clearRecentRecords()

            #expect(try await batch.verify(using: .metal) == [true, true])

            let successRecord = try #require(
                OpalDiagnostics.recentRecords(
                    matching: .init(event: .schnorrBatchVerifySucceeded)
                ).first
            )
            #expect(metalField(named: "selected_backend", in: successRecord)?.value == "metal")
            #expect(metalField(named: "cpu_preparation_duration", in: successRecord) != nil)
            #expect(metalField(named: "gpu_execution_duration", in: successRecord) != nil)
            #expect(metalField(named: "readback_duration", in: successRecord) != nil)
            #expect(
                OpalDiagnostics.recentRecords(
                    matching: .init(event: .schnorrBatchVerifyFallback)
                ).isEmpty
            )
        }
    }

    private func metalField(
        named name: String,
        in record: OpalDiagnostics.Record
    ) -> OpalDiagnostics.Field? {
        record.fields.first { $0.name == name }
    }
}
