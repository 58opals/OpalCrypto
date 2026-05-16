// OpalCryptoDiagnosticsValidator.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

@Suite(.serialized)
struct OpalCryptoDiagnosticsValidator {
    @Test("Successful ECDSA verification records public-safe diagnostics")
    func successfulECDSAVerificationRecordsPublicSafeDiagnostics() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(1)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            let message = Data("opal-diagnostics-ecdsa-message".utf8)
            let signature = try OpalCrypto.Signature.ECDSA.sign(
                message: message,
                privateKey: privateKey,
                format: .der
            )

            OpalDiagnostics.clearRecentRecords()

            #expect(try signature.verify(message: message, publicKey: publicKey))

            let record = try #require(diagnosticRecord(named: OpalCryptoDiagnostics.Event.ecdsaVerifySucceeded))
            #expect(record.category == OpalCryptoDiagnostics.Category.signature)
            #expect(field("operation", in: record)?.value == "verify")
            #expect(field("algorithm", in: record)?.value == "ecdsa")
            #expect(field("format", in: record)?.value == "der")
            #expect(field("message_byte_count", in: record)?.value == String(message.count))
            #expect(field("signature_byte_count", in: record)?.value == String(signature.rawRepresentation.count))
            #expect(field("verification_result", in: record)?.value == "true")
            #expect(field("verification_result", in: record)?.privacy == .public)
        }
    }

    @Test("Malformed key parsing records redacted diagnostics")
    func malformedKeyParsingRecordsRedactedDiagnostics() throws {
        try withDiagnosticsCapture {
            let malformedPrivateKey = Data(repeating: 0x01, count: 31)

            #expect(throws: OpalCrypto.Secp256k1.Error.self) {
                _ = try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: malformedPrivateKey)
            }

            let privateKeyRecord = try #require(diagnosticRecord(named: OpalCryptoDiagnostics.Event.privateKeyParseFailed))
            #expect(privateKeyRecord.category == OpalCryptoDiagnostics.Category.key)
            #expect(field("operation", in: privateKeyRecord)?.value == "private_key_parse")
            #expect(field("input_byte_count", in: privateKeyRecord)?.value == "31")
            #expect(field("error_type", in: privateKeyRecord)?.privacy == .public)
            #expect(field("error_message", in: privateKeyRecord)?.value == "<redacted>")
            #expect(privateKeyRecord.fields.contains { $0.value.contains("010101") } == false)

            OpalDiagnostics.clearRecentRecords()

            let malformedPublicKey = Data([0x05] + Array(repeating: UInt8(0x00), count: 32))
            #expect(throws: OpalCrypto.Secp256k1.Error.self) {
                _ = try OpalCrypto.Secp256k1.PublicKey(rawRepresentation: malformedPublicKey)
            }

            let publicKeyRecord = try #require(diagnosticRecord(named: OpalCryptoDiagnostics.Event.publicKeyParseFailed))
            #expect(publicKeyRecord.category == OpalCryptoDiagnostics.Category.key)
            #expect(field("operation", in: publicKeyRecord)?.value == "public_key_parse")
            #expect(field("input_byte_count", in: publicKeyRecord)?.value == "33")
            #expect(field("error_type", in: publicKeyRecord)?.privacy == .public)
            #expect(field("error_message", in: publicKeyRecord)?.value == "<redacted>")
            #expect(publicKeyRecord.fields.contains { $0.value.contains("050000") } == false)
        }
    }

    @Test("Communication decrypt failure records no key or payload material")
    func communicationDecryptFailureRecordsNoKeyOrPayloadMaterial() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(7)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            let message = Data("diagnostics-secret-message".utf8)
            let ciphertext = try OpalCrypto.Communication.encrypt(
                message: message,
                recipientPublicKey: publicKey,
                paddedPlaintextLength: 32
            )
            var tamperedCiphertextData = ciphertext.rawRepresentation
            tamperedCiphertextData[tamperedCiphertextData.index(before: tamperedCiphertextData.endIndex)] ^= 0x01
            let tamperedCiphertext = try OpalCrypto.Communication.Ciphertext(
                rawRepresentation: tamperedCiphertextData
            )

            OpalDiagnostics.clearRecentRecords()

            #expect(throws: OpalCrypto.Communication.Error.self) {
                _ = try OpalCrypto.Communication.decrypt(
                    tamperedCiphertext,
                    privateKey: privateKey
                )
            }

            let record = try #require(diagnosticRecord(named: OpalCryptoDiagnostics.Event.communicationDecryptFailed))
            #expect(record.category == OpalCryptoDiagnostics.Category.communication)
            #expect(field("operation", in: record)?.value == "decrypt")
            #expect(field("mode", in: record)?.value == "private_key")
            #expect(field("ciphertext_byte_count", in: record)?.value == String(tamperedCiphertextData.count))
            #expect(field("error_type", in: record)?.privacy == .public)
            #expect(field("error_message", in: record)?.value == "<redacted>")
            #expect(field("ciphertext", in: record) == nil)
            #expect(field("plaintext", in: record) == nil)
            #expect(field("private_key", in: record) == nil)
            #expect(field("symmetric_key", in: record) == nil)
            #expect(record.fields.contains { $0.value.contains("diagnostics-secret-message") } == false)
        }
    }

    @Test("Crypto category filter includes diagnostics subcategories")
    func cryptoCategoryFilterIncludesDiagnosticsSubcategories() throws {
        try OpalDiagnostics.withConfiguration(Self.diagnosticsConfiguration) {
            OpalDiagnostics.clearRecentRecords()

            _ = OpalCrypto.Encoding.decodeBase58("0")
            #expect(throws: OpalCrypto.Key.WIF.Error.self) {
                _ = try OpalCrypto.Key.WIF("0")
            }
            OpalDiagnostics.logger(category: .base).record(
                event: "opalcrypto.base.filtered",
                level: .debug
            )

            let events = OpalDiagnostics.recentRecords.map(\.event)
            #expect(events.contains(OpalCryptoDiagnostics.Event.base58DecodeFailed))
            #expect(events.contains(OpalCryptoDiagnostics.Event.base58CheckDecodeFailed))
            #expect(events.contains(OpalCryptoDiagnostics.Event.wifParseFailed))
            #expect(events.contains(OpalDiagnostics.Event(rawValue: "opalcrypto.base.filtered")) == false)

            let encodingRecord = try #require(diagnosticRecord(named: OpalCryptoDiagnostics.Event.base58CheckDecodeFailed))
            #expect(encodingRecord.category == OpalCryptoDiagnostics.Category.encoding)
            #expect(field("input_character_count", in: encodingRecord)?.value == "1")
        }
    }

    private static let diagnosticsConfiguration = OpalDiagnostics.Configuration(
        minimumLevel: .debug,
        categoryFilter: .enabledIncludingSubcategories([OpalCryptoDiagnostics.Category.crypto]),
        bufferPolicy: .enabled(capacity: 1_000)
    )

    private func withDiagnosticsCapture<Success>(_ operation: () throws -> Success) rethrows -> Success {
        try OpalDiagnostics.withConfiguration(Self.diagnosticsConfiguration) {
            OpalDiagnostics.clearRecentRecords()
            return try operation()
        }
    }

    private func diagnosticRecord(
        named event: OpalDiagnostics.Event
    ) -> OpalDiagnostics.Record? {
        OpalDiagnostics.recentRecords(matching: .init(event: event)).first
    }

    private func field(
        _ name: String,
        in record: OpalDiagnostics.Record
    ) -> OpalDiagnostics.Field? {
        record.fields.first { $0.name == name }
    }
}
