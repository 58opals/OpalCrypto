// DiagnosticsIntegrationValidator~Signature.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("Successful ECDSA verification records public-safe diagnostics")
    func validateSuccessfulECDSAVerificationRecordsPublicSafeDiagnostics() throws {
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

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.ecdsaVerifySucceeded))
            #expect(record.category == OpalDiagnostics.Category.signature)
            #expect(field("operation", in: record)?.value == "verify")
            #expect(field("algorithm", in: record)?.value == "ecdsa")
            #expect(field("format", in: record)?.value == "der")
            #expect(field("message_byte_count", in: record)?.value == String(message.count))
            expectPublicField(
                "verification_key_byte_count",
                in: record,
                equals: String(publicKey.rawRepresentation.count)
            )
            #expect(field("signature_byte_count", in: record)?.value == String(signature.rawRepresentation.count))
            expectPublicField("verification_result", in: record, equals: "true")
        }
    }

    @Test("Successful Schnorr verification records public-safe diagnostics")
    func validateSuccessfulSchnorrVerificationRecordsPublicSafeDiagnostics() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(2)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            let digest = try OpalCrypto.Signature.Digest(
                rawRepresentation: Data(repeating: 0x02, count: 32)
            )
            let signature = try OpalCrypto.Signature.Schnorr.sign(
                digest: digest,
                privateKey: privateKey
            )

            OpalDiagnostics.clearRecentRecords()

            #expect(try signature.verify(digest: digest, publicKey: publicKey))

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.schnorrVerifySucceeded))
            #expect(record.category == OpalDiagnostics.Category.signature)
            #expect(field("operation", in: record)?.value == "verify")
            #expect(field("algorithm", in: record)?.value == "schnorr")
            #expect(field("format", in: record)?.value == "bitcoin_cash")
            #expect(field("digest_byte_count", in: record)?.value == "32")
            expectPublicField(
                "verification_key_byte_count",
                in: record,
                equals: String(publicKey.rawRepresentation.count)
            )
            #expect(field("signature_byte_count", in: record)?.value == String(signature.rawRepresentation.count))
            expectPublicField("verification_result", in: record, equals: "true")
        }
    }

    @Test("Signature signing records public-safe private-key lengths")
    func validateSignatureSigningRecordsPublicSafePrivateKeyLengths() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(3)
            let message = Data("opal-diagnostics-sign-message".utf8)
            let digest = try OpalCrypto.Signature.Digest(
                rawRepresentation: Data(repeating: 0x03, count: 32)
            )

            _ = try OpalCrypto.Signature.ECDSA.sign(
                message: message,
                privateKey: privateKey,
                format: .der
            )
            let ecdsaMessageRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.ecdsaSignSucceeded))
            #expect(field("operation", in: ecdsaMessageRecord)?.value == "sign")
            #expect(field("algorithm", in: ecdsaMessageRecord)?.value == "ecdsa")
            expectPublicField("private_key_byte_count", in: ecdsaMessageRecord, equals: "32")
            #expect(field("private_key", in: ecdsaMessageRecord) == nil)

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Signature.ECDSA.sign(
                digest: digest,
                privateKey: privateKey,
                format: .raw
            )
            let ecdsaDigestRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.ecdsaSignSucceeded))
            #expect(field("operation", in: ecdsaDigestRecord)?.value == "sign")
            #expect(field("algorithm", in: ecdsaDigestRecord)?.value == "ecdsa")
            expectPublicField("private_key_byte_count", in: ecdsaDigestRecord, equals: "32")
            #expect(field("private_key", in: ecdsaDigestRecord) == nil)

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Signature.Schnorr.sign(
                digest: digest,
                privateKey: privateKey
            )
            let schnorrRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.schnorrSignSucceeded))
            #expect(field("operation", in: schnorrRecord)?.value == "sign")
            #expect(field("algorithm", in: schnorrRecord)?.value == "schnorr")
            expectPublicField("private_key_byte_count", in: schnorrRecord, equals: "32")
            #expect(field("private_key", in: schnorrRecord) == nil)
        }
    }

    @Test("SigningKey signing records public-safe private-key lengths")
    func validateSigningKeySigningRecordsPublicSafePrivateKeyLengths() throws {
        try withDiagnosticsCapture {
            let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(31).makeSigningKey()
            let message = Data("opal-diagnostics-signing-key-message".utf8)
            let digest = try OpalCrypto.Signature.Digest(
                rawRepresentation: Data(repeating: 0x31, count: 32)
            )

            _ = try signingKey.signECDSA(
                message: message,
                format: .der
            )
            let ecdsaRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.ecdsaSignSucceeded))
            #expect(field("operation", in: ecdsaRecord)?.value == "sign")
            #expect(field("algorithm", in: ecdsaRecord)?.value == "ecdsa")
            expectPublicField("private_key_byte_count", in: ecdsaRecord, equals: "32")
            #expect(field("private_key", in: ecdsaRecord) == nil)
            #expect(field("signing_key", in: ecdsaRecord) == nil)

            OpalDiagnostics.clearRecentRecords()

            _ = try signingKey.signSchnorr(digest: digest)
            let schnorrRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.schnorrSignSucceeded))
            #expect(field("operation", in: schnorrRecord)?.value == "sign")
            #expect(field("algorithm", in: schnorrRecord)?.value == "schnorr")
            expectPublicField("private_key_byte_count", in: schnorrRecord, equals: "32")
            #expect(field("private_key", in: schnorrRecord) == nil)
            #expect(field("signing_key", in: schnorrRecord) == nil)
        }
    }

    @Test("Malformed key parsing records redacted diagnostics")
    func validateMalformedKeyParsingRecordsRedactedDiagnostics() throws {
        try withDiagnosticsCapture {
            let malformedPrivateKey = Data(repeating: 0x01, count: 31)

            #expect(throws: OpalCrypto.Secp256k1.Error.self) {
                _ = try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: malformedPrivateKey)
            }

            let privateKeyRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.privateKeyParseFailed))
            #expect(privateKeyRecord.category == OpalDiagnostics.Category.key)
            #expect(privateKeyRecord.level == .error)
            #expect(field("operation", in: privateKeyRecord)?.value == "private_key_parse")
            #expect(field("input_byte_count", in: privateKeyRecord)?.value == "31")
            #expect(field("error_code", in: privateKeyRecord)?.value == "invalid_private_key_length")
            #expect(field("error_type", in: privateKeyRecord)?.privacy == .public)
            #expect(field("error_message", in: privateKeyRecord)?.value == "<redacted>")
            #expect(field("private_key", in: privateKeyRecord) == nil)
            #expect(privateKeyRecord.fields.contains { $0.value.contains("010101") } == false)

            OpalDiagnostics.clearRecentRecords()

            let malformedPublicKey = Data([0x05] + Array(repeating: UInt8(0x00), count: 32))
            #expect(throws: OpalCrypto.Secp256k1.Error.self) {
                _ = try OpalCrypto.Secp256k1.PublicKey(rawRepresentation: malformedPublicKey)
            }

            let publicKeyRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseFailed))
            #expect(publicKeyRecord.category == OpalDiagnostics.Category.key)
            #expect(publicKeyRecord.level == .error)
            #expect(field("operation", in: publicKeyRecord)?.value == "public_key_parse")
            #expect(field("input_byte_count", in: publicKeyRecord)?.value == "33")
            #expect(field("error_code", in: publicKeyRecord)?.value == "invalid_public_key_prefix")
            #expect(field("error_type", in: publicKeyRecord)?.privacy == .public)
            #expect(field("error_message", in: publicKeyRecord)?.value == "<redacted>")
            #expect(field("public_key", in: publicKeyRecord) == nil)
            #expect(publicKeyRecord.fields.contains { $0.value.contains("050000") } == false)
        }
    }
}
