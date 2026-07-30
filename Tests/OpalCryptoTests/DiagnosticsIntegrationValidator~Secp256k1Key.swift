// DiagnosticsIntegrationValidator~Secp256k1Key.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("Tweak-add failures record stable error codes")
    func validateTweakAddFailuresRecordStableErrorCodes() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(1)
            let cancelingTweak = try OpalCrypto.Secp256k1.Scalar(
                rawRepresentation: try Data(
                    hexadecimal: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"
                )
            )

            #expect(throws: OpalCrypto.Secp256k1.Error.self) {
                _ = try OpalCrypto.Secp256k1.tweakAddPrivateKey(
                    privateKey,
                    tweak: cancelingTweak
                )
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.privateKeyTweakAddFailed))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(record.level == .error)
            #expect(field("operation", in: record)?.value == "private_key_tweak_add")
            expectPublicField("private_key_byte_count", in: record, equals: "32")
            expectPublicField("tweak_byte_count", in: record, equals: "32")
            #expect(field("error_code", in: record)?.value == "invalid_derived_key")
            #expect(field("private_key", in: record) == nil)
            #expect(field("tweak", in: record) == nil)
            #expect(record.fields.contains { $0.value.contains("FFFFFFFF") } == false)
        }
    }

    @Test("Public-key derivation and tweak-add avoid nested parse diagnostics")
    func validatePublicKeyDerivationAndTweakAddAvoidNestedParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(23)
            let tweak = try OpalCryptoTestSupport.makeScalar(1)

            OpalDiagnostics.clearRecentRecords()

            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

            let deriveRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyDeriveSucceeded))
            #expect(deriveRecord.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: deriveRecord)?.value == "public_key_derive")
            #expect(field("algorithm", in: deriveRecord)?.value == "secp256k1")
            expectPublicField("private_key_byte_count", in: deriveRecord, equals: "32")
            #expect(field("output_byte_count", in: deriveRecord)?.value == "33")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseSucceeded) == nil)

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Secp256k1.tweakAddPublicKey(publicKey, tweak: tweak)

            let tweakRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyTweakAddSucceeded))
            #expect(tweakRecord.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: tweakRecord)?.value == "public_key_tweak_add")
            #expect(field("algorithm", in: tweakRecord)?.value == "secp256k1")
            expectPublicField("public_key_byte_count", in: tweakRecord, equals: "33")
            expectPublicField("tweak_byte_count", in: tweakRecord, equals: "32")
            #expect(field("output_byte_count", in: tweakRecord)?.value == "33")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseSucceeded) == nil)
        }
    }

    @Test("Public-key batch derivation records public-safe key counts")
    func validatePublicKeyBatchDerivationRecordsPublicSafeKeyCounts() async throws {
        try await withDiagnosticsCapture {
            let privateKeys = try [
                OpalCryptoTestSupport.makeTypedPrivateKey(24),
                OpalCryptoTestSupport.makeTypedPrivateKey(25)
            ]

            _ = try await OpalCrypto.Secp256k1.derivePublicKeys(from: privateKeys)

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.publicKeysDeriveSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: record)?.value == "public_key_batch_derive")
            #expect(field("algorithm", in: record)?.value == "secp256k1")
            #expect(field("key_count", in: record)?.value == "2")
            expectPublicField("private_key_byte_count", in: record, equals: "32")
            #expect(field("output_key_count", in: record)?.value == "2")
            #expect(field("private_key", in: record) == nil)
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseSucceeded) == nil)
        }
    }

    @Test("Shared-secret batch derivation records public-safe key counts")
    func validateSharedSecretBatchDerivationRecordsPublicSafeKeyCounts() async throws {
        try await withDiagnosticsCapture {
            let scanPrivateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(26)
            let publicKeys = try [
                OpalCryptoTestSupport.makeTypedPrivateKey(27),
                OpalCryptoTestSupport.makeTypedPrivateKey(28)
            ].map {
                try OpalCrypto.Secp256k1.derivePublicKey(from: $0)
            }

            OpalDiagnostics.clearRecentRecords()

            _ = try await OpalCrypto.Secp256k1.deriveSharedSecrets(
                privateKey: scanPrivateKey,
                publicKeys: publicKeys
            )

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretsDeriveSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: record)?.value == "shared_secret_batch_derive")
            #expect(field("algorithm", in: record)?.value == "secp256k1")
            #expect(field("public_key_count", in: record)?.value == "2")
            expectPublicField("private_key_byte_count", in: record, equals: "32")
            expectPublicField("public_key_byte_count", in: record, equals: "33")
            #expect(field("output_secret_count", in: record)?.value == "2")
            #expect(field("private_key", in: record) == nil)
            #expect(field("public_key", in: record) == nil)
            #expect(field("shared_secret", in: record) == nil)
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretParseSucceeded) == nil)
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseSucceeded) == nil)
        }
    }

    @Test("Shared-point x derivation records only public-safe lengths")
    func validateSharedPointXDerivationRecordsOnlyPublicSafeLengths() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(29)
            let peerPrivateKey =
                try OpalCryptoTestSupport.makeTypedPrivateKey(30)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(
                from: peerPrivateKey
            )

            OpalDiagnostics.clearRecentRecords()

            let coordinate =
                OpalCrypto.Secp256k1.deriveSharedPointXCoordinate(
                    signingKey: privateKey.makeSigningKey(),
                    publicKey: publicKey
                )

            let record = try #require(
                diagnosticRecord(
                    named: OpalDiagnostics.Event
                        .sharedPointXDeriveSucceeded
                )
            )
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(record.level == .debug)
            #expect(
                field("operation", in: record)?.value
                    == "shared_point_x_derive"
            )
            #expect(field("algorithm", in: record)?.value == "secp256k1")
            expectPublicField(
                "private_key_byte_count",
                in: record,
                equals: "32"
            )
            expectPublicField(
                "public_key_byte_count",
                in: record,
                equals: "33"
            )
            #expect(field("output_byte_count", in: record)?.value == "32")
            #expect(field("private_key", in: record) == nil)
            #expect(field("public_key", in: record) == nil)
            #expect(field("shared_point_x", in: record) == nil)
            let coordinateHex = coordinate.rawRepresentation
                .map { String(format: "%02x", $0) }
                .joined()
            #expect(
                record.fields.contains {
                    $0.value.contains(coordinateHex)
                } == false
            )
        }
    }

    @Test("Uncompressed verification-key parsing records normalized output length")
    func validateUncompressedVerificationKeyParsingRecordsNormalizedOutputLength() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(11)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

            OpalDiagnostics.clearRecentRecords()

            let verificationKey = try OpalCrypto.Signature.VerificationKey(
                rawRepresentation: publicKey.uncompressedRepresentation
            )

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.verificationKeyParseSucceeded))
            #expect(verificationKey.rawRepresentation.count == 33)
            #expect(record.category == OpalDiagnostics.Category.signature)
            #expect(field("operation", in: record)?.value == "verification_key_parse")
            #expect(field("algorithm", in: record)?.value == "secp256k1")
            #expect(field("format", in: record)?.value == "sec1_uncompressed")
            #expect(field("input_byte_count", in: record)?.value == "65")
            #expect(field("output_byte_count", in: record)?.value == "33")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseSucceeded) == nil)
        }
    }

    @Test("Verification-key derivation records public-safe key lengths")
    func validateVerificationKeyDerivationRecordsPublicSafeKeyLengths() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(12)

            _ = try OpalCrypto.Signature.deriveVerificationKey(from: privateKey)

            let record = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.verificationKeyDeriveSucceeded)
            )
            #expect(record.category == OpalDiagnostics.Category.signature)
            #expect(record.level == .debug)
            #expect(field("operation", in: record)?.value == "verification_key_derive")
            #expect(field("algorithm", in: record)?.value == "secp256k1")
            expectPublicField("input_byte_count", in: record, equals: "32")
            expectPublicField("private_key_byte_count", in: record, equals: "32")
            expectPublicField("output_byte_count", in: record, equals: "33")
            expectPublicField("verification_key_byte_count", in: record, equals: "33")
            #expect(field("private_key", in: record) == nil)
            #expect(field("verification_key", in: record) == nil)
        }
    }
}
