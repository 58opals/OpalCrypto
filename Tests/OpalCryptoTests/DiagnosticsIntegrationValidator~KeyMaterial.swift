// DiagnosticsIntegrationValidator~KeyMaterial.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("Shared-secret raw parsing records parse diagnostics")
    func validateSharedSecretRawParsingRecordsParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let validSecret = Data(repeating: 0x01, count: 32)

            _ = try OpalCrypto.Secp256k1.SharedSecret(rawRepresentation: validSecret)

            let successRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretParseSucceeded))
            #expect(successRecord.category == OpalDiagnostics.Category.key)
            #expect(successRecord.level == .debug)
            #expect(field("operation", in: successRecord)?.value == "shared_secret_parse")
            expectPublicField("input_byte_count", in: successRecord, equals: "32")
            expectPublicField("output_byte_count", in: successRecord, equals: "32")
            #expect(field("shared_secret", in: successRecord) == nil)

            OpalDiagnostics.clearRecentRecords()

            #expect(throws: OpalCrypto.Secp256k1.Error.self) {
                _ = try OpalCrypto.Secp256k1.SharedSecret(
                    rawRepresentation: Data(repeating: 0x01, count: 31)
                )
            }

            let failureRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretParseFailed))
            #expect(failureRecord.category == OpalDiagnostics.Category.key)
            #expect(failureRecord.level == .error)
            #expect(field("operation", in: failureRecord)?.value == "shared_secret_parse")
            expectPublicField("input_byte_count", in: failureRecord, equals: "31")
            #expect(field("error_code", in: failureRecord)?.value == "invalid_derived_key")
            #expect(field("error_type", in: failureRecord)?.privacy == .public)
            #expect(field("error_message", in: failureRecord)?.value == "<redacted>")
            #expect(field("shared_secret", in: failureRecord) == nil)
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretDeriveFailed) == nil)
        }
    }

    @Test("Shared-secret derivation does not emit nested parse diagnostics")
    func validateSharedSecretDerivationDoesNotEmitNestedParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(19)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Secp256k1.deriveSharedSecret(
                privateKey: privateKey,
                publicKey: publicKey
            )

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretDeriveSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: record)?.value == "shared_secret_derive")
            #expect(field("algorithm", in: record)?.value == "secp256k1")
            #expect(field("private_key_byte_count", in: record)?.value == "32")
            #expect(field("private_key_byte_count", in: record)?.privacy == .public)
            #expect(field("public_key_byte_count", in: record)?.value == String(publicKey.rawRepresentation.count))
            #expect(field("public_key_byte_count", in: record)?.privacy == .public)
            #expect(field("output_byte_count", in: record)?.value == "32")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretParseSucceeded) == nil)
        }
    }

    @Test("Extended-key validated accessors do not emit parse diagnostics")
    func validateExtendedKeyValidatedAccessorsDoNotEmitParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let seed = try OpalCrypto.Key.Seed(
                rawRepresentation: Data((0..<16).map { UInt8($0) })
            )
            let extendedPrivateKey = try OpalCrypto.Key.ExtendedPrivate.root(seed: seed)
            let extendedPublicKey = extendedPrivateKey.publicKey

            OpalDiagnostics.clearRecentRecords()

            _ = extendedPrivateKey.privateKey
            _ = extendedPublicKey.publicKey

            #expect(diagnosticRecord(named: OpalDiagnostics.Event.privateKeyParseSucceeded) == nil)
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseSucceeded) == nil)
            #expect(OpalDiagnostics.recentRecords.isEmpty)
        }
    }

    @Test("Extended-private root records public-safe component lengths")
    func validateExtendedPrivateRootRecordsPublicSafeComponentLengths() throws {
        try withDiagnosticsCapture {
            let seed = try OpalCrypto.Key.Seed(
                rawRepresentation: Data((0..<16).map { UInt8($0) })
            )

            _ = try OpalCrypto.Key.ExtendedPrivate.root(seed: seed)

            let record = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.extendedPrivateRootSucceeded)
            )
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: record)?.value == "extended_private_root")
            #expect(field("format", in: record)?.value == "bip32")
            expectPublicField("seed_byte_count", in: record, equals: "16")
            expectPublicField("private_key_byte_count", in: record, equals: "32")
            expectPublicField("chain_code_byte_count", in: record, equals: "32")
            #expect(field("seed", in: record) == nil)
            #expect(field("private_key", in: record) == nil)
            #expect(field("chain_code", in: record) == nil)
        }
    }

    @Test("Extended-key parsing records public-safe component lengths")
    func validateExtendedKeyParsingRecordsPublicSafeComponentLengths() throws {
        try withDiagnosticsCapture {
            let seed = try OpalCrypto.Key.Seed(
                rawRepresentation: Data((0..<16).map { UInt8($0) })
            )
            let extendedPrivateKey = try OpalCrypto.Key.ExtendedPrivate.root(seed: seed)
            let extendedPrivateKeyString = extendedPrivateKey.serialize()
            let extendedPublicKeyString = extendedPrivateKey.publicKey.serialize()

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Key.ExtendedPrivate(extendedPrivateKeyString)
            _ = try OpalCrypto.Key.ExtendedPublic(extendedPublicKeyString)

            let privateRecord = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.extendedPrivateParseSucceeded)
            )
            #expect(privateRecord.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: privateRecord)?.value == "extended_private_parse")
            #expect(field("format", in: privateRecord)?.value == "bip32_xprv")
            expectPublicField(
                "input_character_count",
                in: privateRecord,
                equals: String(extendedPrivateKeyString.count)
            )
            expectPublicField("private_key_byte_count", in: privateRecord, equals: "32")
            expectPublicField("chain_code_byte_count", in: privateRecord, equals: "32")
            #expect(field("private_key", in: privateRecord) == nil)
            #expect(field("chain_code", in: privateRecord) == nil)

            let publicRecord = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.extendedPublicParseSucceeded)
            )
            #expect(publicRecord.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: publicRecord)?.value == "extended_public_parse")
            #expect(field("format", in: publicRecord)?.value == "bip32_xpub")
            expectPublicField(
                "input_character_count",
                in: publicRecord,
                equals: String(extendedPublicKeyString.count)
            )
            expectPublicField("public_key_byte_count", in: publicRecord, equals: "33")
            expectPublicField("chain_code_byte_count", in: publicRecord, equals: "32")
            #expect(field("public_key", in: publicRecord) == nil)
            #expect(field("chain_code", in: publicRecord) == nil)
        }
    }
}
