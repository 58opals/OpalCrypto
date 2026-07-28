// DiagnosticsIntegrationValidator~Communication.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("Private-key decryption result does not emit symmetric-key parse diagnostics")
    func validatePrivateKeyDecryptionResultDoesNotEmitSymmetricKeyParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(13)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            let ciphertext = try OpalCrypto.Communication.encrypt(
                message: Data("diagnostics-decrypt-success".utf8),
                recipientPublicKey: publicKey,
                paddedPlaintextLength: 32,
                maximumCiphertextByteCount: 81
            )

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Communication.decrypt(
                ciphertext,
                privateKey: privateKey,
                maximumCiphertextByteCount: 81
            )

            let beginRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.communicationDecryptBegin))
            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.communicationDecryptSucceeded))
            #expect(field("mode", in: beginRecord)?.value == "private_key")
            #expect(field("private_key_byte_count", in: beginRecord)?.value == "32")
            #expect(field("private_key_byte_count", in: beginRecord)?.privacy == .public)
            #expect(record.category == OpalDiagnostics.Category.communication)
            #expect(field("operation", in: record)?.value == "decrypt")
            #expect(field("ciphertext_byte_count", in: record)?.value == String(ciphertext.rawRepresentation.count))
            #expect(field("private_key_byte_count", in: record)?.value == "32")
            #expect(field("plaintext_byte_count", in: record)?.value == "27")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.communicationSymmetricKeyParseSucceeded) == nil)
        }
    }

    @Test("Symmetric-key communication decrypt records public-safe key length")
    func validateSymmetricKeyCommunicationDecryptRecordsPublicSafeKeyLength() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(29)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            let ciphertext = try OpalCrypto.Communication.encrypt(
                message: Data("symmetric-diagnostics".utf8),
                recipientPublicKey: publicKey,
                maximumCiphertextByteCount: 81
            )
            let decrypted = try OpalCrypto.Communication.decrypt(
                ciphertext,
                privateKey: privateKey,
                maximumCiphertextByteCount: 81
            )

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Communication.decrypt(
                ciphertext,
                symmetricKey: decrypted.symmetricKey,
                maximumCiphertextByteCount: 81
            )

            let beginRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.communicationDecryptBegin))
            let successRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.communicationDecryptSucceeded))
            #expect(field("mode", in: beginRecord)?.value == "symmetric_key")
            #expect(field("symmetric_key_byte_count", in: beginRecord)?.value == "32")
            #expect(field("symmetric_key_byte_count", in: beginRecord)?.privacy == .public)
            #expect(successRecord.category == OpalDiagnostics.Category.communication)
            #expect(field("operation", in: successRecord)?.value == "decrypt")
            #expect(field("mode", in: successRecord)?.value == "symmetric_key")
            #expect(field("plaintext_byte_count", in: successRecord)?.value == "21")
            #expect(field("symmetric_key_byte_count", in: successRecord)?.value == "32")
        }
    }

    @Test("Symmetric-key parsing records public-safe key length")
    func validateSymmetricKeyParsingRecordsPublicSafeKeyLength() throws {
        try withDiagnosticsCapture {
            _ = try OpalCrypto.Communication.SymmetricKey(
                rawRepresentation: Data(repeating: 0x42, count: 32)
            )

            let record = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.communicationSymmetricKeyParseSucceeded)
            )
            #expect(record.category == OpalDiagnostics.Category.communication)
            #expect(field("operation", in: record)?.value == "symmetric_key_parse")
            expectPublicField("symmetric_key_byte_count", in: record, equals: "32")
            #expect(field("input_byte_count", in: record)?.value == "32")
            #expect(field("symmetric_key", in: record) == nil)
        }
    }

    @Test("Communication ciphertext parsing records envelope length boundaries")
    func validateCommunicationCiphertextParsingRecordsEnvelopeLengthBoundaries() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(33)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            let ciphertext = try OpalCrypto.Communication.encrypt(
                message: Data("ciphertext-diagnostics".utf8),
                recipientPublicKey: publicKey,
                maximumCiphertextByteCount: 81
            )

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Communication.Ciphertext(
                rawRepresentation: ciphertext.rawRepresentation,
                maximumCiphertextByteCount: 81
            )

            let successRecord = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.communicationCiphertextParseSucceeded)
            )
            #expect(successRecord.category == OpalDiagnostics.Category.communication)
            #expect(successRecord.level == .debug)
            #expect(field("operation", in: successRecord)?.value == "ciphertext_parse")
            expectPublicField(
                "ciphertext_byte_count",
                in: successRecord,
                equals: String(ciphertext.rawRepresentation.count)
            )
            expectPublicField(
                "minimum_ciphertext_byte_count",
                in: successRecord,
                equals: String(CommunicationBoxModel.minimumCiphertextLength)
            )
            #expect(field("ciphertext", in: successRecord) == nil)

            OpalDiagnostics.clearRecentRecords()

            let shortCiphertext = Data(
                repeating: 0,
                count: CommunicationBoxModel.minimumCiphertextLength - 1
            )
            #expect(throws: OpalCrypto.Communication.Error.self) {
                _ = try OpalCrypto.Communication.Ciphertext(
                    rawRepresentation: shortCiphertext,
                    maximumCiphertextByteCount: 81
                )
            }

            let failureRecord = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.communicationCiphertextParseFailed)
            )
            #expect(failureRecord.category == OpalDiagnostics.Category.communication)
            #expect(failureRecord.level == .error)
            #expect(field("operation", in: failureRecord)?.value == "ciphertext_parse")
            expectPublicField(
                "ciphertext_byte_count",
                in: failureRecord,
                equals: String(shortCiphertext.count)
            )
            expectPublicField(
                "minimum_ciphertext_byte_count",
                in: failureRecord,
                equals: String(CommunicationBoxModel.minimumCiphertextLength)
            )
            #expect(field("error_code", in: failureRecord)?.value == "invalid_ciphertext")
            #expect(field("error_type", in: failureRecord)?.privacy == .public)
            #expect(field("error_message", in: failureRecord)?.value == "<redacted>")
            #expect(field("ciphertext", in: failureRecord) == nil)
        }
    }

    @Test("Communication encrypt default padding diagnostics report resolved length")
    func validateCommunicationEncryptDefaultPaddingDiagnosticsReportResolvedLength() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(31)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Communication.encrypt(
                message: Data("abc".utf8),
                recipientPublicKey: publicKey,
                maximumCiphertextByteCount: 65
            )

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.communicationEncryptSucceeded))
            #expect(field("plaintext_byte_count", in: record)?.value == "3")
            #expect(field("padded_plaintext_length", in: record)?.value == "16")
            #expect(field("has_explicit_padding", in: record)?.value == "false")
        }
    }

    @Test("Communication encrypt invalid explicit padding diagnostics report requested length")
    func validateCommunicationEncryptInvalidExplicitPaddingDiagnosticsReportRequestedLength() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(37)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

            OpalDiagnostics.clearRecentRecords()

            #expect(throws: OpalCrypto.Communication.Error.invalidPaddedPlaintextLength(minimum: 8, actual: 5)) {
                _ = try OpalCrypto.Communication.encrypt(
                    message: Data("abcd".utf8),
                    recipientPublicKey: publicKey,
                    paddedPlaintextLength: 5,
                    maximumCiphertextByteCount: 65
                )
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.communicationEncryptFailed))
            #expect(field("plaintext_byte_count", in: record)?.value == "4")
            #expect(field("minimum_padded_plaintext_length", in: record)?.value == "8")
            #expect(field("padded_plaintext_length", in: record)?.value == "5")
            #expect(field("has_explicit_padding", in: record)?.value == "true")
            #expect(field("error_code", in: record)?.value == "invalid_padded_plaintext_length")
        }
    }

    @Test("Communication ciphertext budget failures record a stable public error code")
    func validateCommunicationCiphertextBudgetFailuresRecordStablePublicErrorCode() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(41)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

            OpalDiagnostics.clearRecentRecords()

            #expect(
                throws: OpalCrypto.Communication.Error
                    .ciphertextByteCountExceedsMaximum(maximum: 64, actual: 65)
            ) {
                _ = try OpalCrypto.Communication.encrypt(
                    message: Data(),
                    recipientPublicKey: publicKey,
                    maximumCiphertextByteCount: 64
                )
            }

            let record = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.communicationEncryptFailed)
            )
            expectPublicField(
                "maximum_ciphertext_byte_count",
                in: record,
                equals: "64"
            )
            #expect(
                field("error_code", in: record)?.value
                    == "ciphertext_byte_count_exceeds_maximum"
            )
        }
    }
}
