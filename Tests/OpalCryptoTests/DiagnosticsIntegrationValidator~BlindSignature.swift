// DiagnosticsIntegrationValidator~BlindSignature.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("Blind-signature finalization records public-safe request-scalar length")
    func validateBlindSignatureFinalizationRecordsPublicSafeRequestScalarLength() async throws {
        try await withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(4)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            let signer = try OpalCrypto.BlindSignature.Signer()
            let digest = try OpalCrypto.Signature.Digest(
                rawRepresentation: Data(repeating: 0x04, count: 32)
            )
            let request = try OpalCrypto.BlindSignature.Request(
                signerPublicKey: publicKey,
                noncePoint: signer.noncePoint,
                messageDigest: digest
            )

            let requestRecord = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.blindSignatureRequestSucceeded)
            )
            #expect(requestRecord.category == OpalDiagnostics.Category.blindSignature)
            #expect(field("operation", in: requestRecord)?.value == "request")
            expectPublicField("request_scalar_byte_count", in: requestRecord, equals: "32")

            let response = try await signer.sign(
                privateKey: privateKey,
                requestScalar: request.scalar
            )

            OpalDiagnostics.clearRecentRecords()

            _ = try request.finalize(responseScalar: response)

            let record = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.blindSignatureUnblindSucceeded)
            )
            #expect(record.category == OpalDiagnostics.Category.blindSignature)
            #expect(field("operation", in: record)?.value == "unblind")
            expectPublicField("request_scalar_byte_count", in: record, equals: "32")
            expectPublicField("response_scalar_byte_count", in: record, equals: "32")
            #expect(field("signature_byte_count", in: record)?.value == "64")
            #expect(field("request_scalar", in: record) == nil)
            #expect(field("response_scalar", in: record) == nil)

            let verifyRecord = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.blindSignatureVerifySucceeded)
            )
            #expect(verifyRecord.category == OpalDiagnostics.Category.blindSignature)
            #expect(field("operation", in: verifyRecord)?.value == "unblind")
            #expect(field("signature_byte_count", in: verifyRecord)?.value == "64")
            expectPublicField("verification_result", in: verifyRecord, equals: "true")
        }
    }
}
