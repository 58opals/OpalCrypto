// DiagnosticsIntegrationValidator~CommunicationFailure.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("Communication decrypt failure records no key or payload material")
    func validateCommunicationDecryptFailureRecordsNoKeyOrPayloadMaterial() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(7)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            let message = Data("diagnostics-secret-message".utf8)
            let ciphertext = try OpalCrypto.Communication.encrypt(
                message: message,
                recipientPublicKey: publicKey,
                paddedPlaintextLength: 32,
                maximumCiphertextByteCount: 81
            )
            var tamperedCiphertextData = ciphertext.rawRepresentation
            tamperedCiphertextData[tamperedCiphertextData.index(before: tamperedCiphertextData.endIndex)] ^= 0x01
            let tamperedCiphertext = try OpalCrypto.Communication.Ciphertext(
                rawRepresentation: tamperedCiphertextData,
                maximumCiphertextByteCount: 81
            )

            OpalDiagnostics.clearRecentRecords()

            #expect(throws: OpalCrypto.Communication.Error.self) {
                _ = try OpalCrypto.Communication.decrypt(
                    tamperedCiphertext,
                    privateKey: privateKey,
                    maximumCiphertextByteCount: 81
                )
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.communicationDecryptFailed))
            #expect(record.category == OpalDiagnostics.Category.communication)
            #expect(record.level == .error)
            #expect(field("operation", in: record)?.value == "decrypt")
            #expect(field("mode", in: record)?.value == "private_key")
            #expect(field("ciphertext_byte_count", in: record)?.value == String(tamperedCiphertextData.count))
            #expect(field("private_key_byte_count", in: record)?.value == "32")
            #expect(field("private_key_byte_count", in: record)?.privacy == .public)
            #expect(field("error_code", in: record)?.value == "invalid_ciphertext")
            #expect(field("error_type", in: record)?.privacy == .public)
            #expect(field("error_message", in: record)?.value == "<redacted>")
            #expect(field("ciphertext", in: record) == nil)
            #expect(field("plaintext", in: record) == nil)
            #expect(field("private_key", in: record) == nil)
            #expect(field("symmetric_key", in: record) == nil)
            #expect(record.fields.contains { $0.value.contains("diagnostics-secret-message") } == false)
        }
    }

    @Test("Communication decrypt failure records ciphertext length boundaries")
    func validateCommunicationDecryptFailureRecordsCiphertextLengthBoundaries() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(9)
            let tooShortCiphertext = OpalCrypto.Communication.Ciphertext(
                unchecked: Data([0x02])
            )

            #expect(throws: OpalCrypto.Communication.Error.self) {
                _ = try OpalCrypto.Communication.decrypt(
                    tooShortCiphertext,
                    privateKey: privateKey,
                    maximumCiphertextByteCount: 1
                )
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.communicationDecryptFailed))
            #expect(record.category == OpalDiagnostics.Category.communication)
            #expect(record.level == .error)
            #expect(field("operation", in: record)?.value == "decrypt")
            #expect(field("mode", in: record)?.value == "private_key")
            expectPublicField("ciphertext_byte_count", in: record, equals: "1")
            expectPublicField(
                "minimum_ciphertext_byte_count",
                in: record,
                equals: String(CommunicationBoxModel.minimumCiphertextLength)
            )
            expectPublicField("private_key_byte_count", in: record, equals: "32")
            #expect(field("error_code", in: record)?.value == "invalid_ciphertext")
            #expect(field("ciphertext", in: record) == nil)
            #expect(field("private_key", in: record) == nil)
        }
    }
}
