// DiagnosticsIntegrationValidator.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

@Suite(.serialized)
struct DiagnosticsIntegrationValidator {
    @Test("OpalDiagnostics catalog exposes stable typed values")
    func opalDiagnosticsCatalogExposesStableTypedValues() {
        let category: OpalDiagnostics.Category = .key
        let event: OpalDiagnostics.Event = .wifParseFailed
        let level: OpalDiagnostics.Level = .error

        #expect(category == OpalDiagnostics.Category.key)
        #expect(event == OpalDiagnostics.Event.wifParseFailed)
        #expect(level == .error)
    }

    @Test("Signature DER diagnostics keep DER-specific error codes")
    func validateSignatureDERDiagnosticsKeepDERSpecificErrorCodes() throws {
        let secpErrorCode = try #require(
            OpalDiagnostics.Field.errorFields(OpalCrypto.Secp256k1.Error.invalidDER)
                .first { $0.name == "error_code" }?
                .value
        )
        let signatureErrorCode = try #require(
            OpalDiagnostics.Field.errorFields(OpalCrypto.Signature.Error.invalidDER)
                .first { $0.name == "error_code" }?
                .value
        )

        #expect(secpErrorCode == "invalid_der")
        #expect(signatureErrorCode == "invalid_der")
    }

    @Test("Base58Check diagnostics report normalized minimum payload lengths")
    func validateBase58CheckDiagnosticsReportNormalizedMinimumPayloadLengths() throws {
        try withDiagnosticsCapture {
            #expect(throws: Base58CheckCodec.Error.self) {
                _ = try Base58CheckCodec.decode("0", minimumPayloadLength: -4)
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.base58CheckDecodeFailed))
            #expect(field("minimum_payload_length", in: record)?.value == "0")

            OpalDiagnostics.clearRecentRecords()

            let validBase58Check = Base58CheckCodec.encode(payload: Data([0x01]))
            let invalidChecksum = String(validBase58Check.dropLast()) + (validBase58Check.last == "1" ? "2" : "1")
            #expect(throws: Base58CheckCodec.Error.invalidChecksum) {
                _ = try Base58CheckCodec.decode(invalidChecksum, minimumPayloadLength: -4)
            }

            let checksumRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.base58CheckDecodeFailed))
            #expect(field("minimum_payload_length", in: checksumRecord)?.value == "0")
        }
    }

    @Test("Default OpalDiagnostics configuration keeps OpalCrypto silent")
    func defaultOpalDiagnosticsConfigurationKeepsOpalCryptoSilent() throws {
        try OpalDiagnostics.withConfiguration(.init()) {
            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: Data(repeating: 0x01, count: 32)
            )

            #expect(OpalDiagnostics.recentRecords.isEmpty)
        }
    }

    @Test("OpalDiagnostics trace wrapper propagates current trace into records")
    func opalDiagnosticsTraceWrapperPropagatesCurrentTraceIntoRecords() throws {
        try withDiagnosticsCapture {
            let traceID = OpalDiagnostics.TraceID(rawValue: "wallet-diagnostics-flow")

            try OpalDiagnostics.withTraceID(traceID) {
                _ = try OpalCrypto.Secp256k1.PrivateKey(
                    rawRepresentation: Data(repeating: 0x01, count: 32)
                )
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.privateKeyParseSucceeded))
            #expect(record.traceID == traceID)
            #expect(OpalDiagnostics.currentTraceID == nil)
        }
    }

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

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.ecdsaVerifySucceeded))
            #expect(record.category == OpalDiagnostics.Category.signature)
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

            let privateKeyRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.privateKeyParseFailed))
            #expect(privateKeyRecord.category == OpalDiagnostics.Category.key)
            #expect(privateKeyRecord.level == .error)
            #expect(field("operation", in: privateKeyRecord)?.value == "private_key_parse")
            #expect(field("input_byte_count", in: privateKeyRecord)?.value == "31")
            #expect(field("error_code", in: privateKeyRecord)?.value == "invalid_private_key_length")
            #expect(field("error_type", in: privateKeyRecord)?.privacy == .public)
            #expect(field("error_message", in: privateKeyRecord)?.value == "<redacted>")
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
            #expect(publicKeyRecord.fields.contains { $0.value.contains("050000") } == false)
        }
    }

    @Test("Hashing facade records public-safe boundary diagnostics")
    func hashingFacadeRecordsPublicSafeBoundaryDiagnostics() throws {
        try withDiagnosticsCapture {
            let payload = Data("diagnostics-hash-payload".utf8)

            let digest = OpalCrypto.Hashing.hash160(payload)

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.hash160Succeeded))
            #expect(record.category == OpalDiagnostics.Category.hashing)
            #expect(record.level == .debug)
            #expect(field("operation", in: record)?.value == "hash")
            #expect(field("algorithm", in: record)?.value == "hash160")
            #expect(field("input_byte_count", in: record)?.value == String(payload.count))
            #expect(field("output_byte_count", in: record)?.value == String(digest.count))
            #expect(record.fields.contains { $0.value.contains("diagnostics-hash-payload") } == false)
        }
    }

    @Test("PBKDF2 failures record stable public error codes without password material")
    func pbkdf2FailuresRecordStablePublicErrorCodesWithoutPasswordMaterial() throws {
        try withDiagnosticsCapture {
            let password = Data("wallet-password-material".utf8)
            let salt = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8))

            #expect(throws: OpalCrypto.KeyDerivation.Error.self) {
                _ = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                    password: password,
                    salt: salt,
                    iterationCount: 0,
                    derivedKeyLength: 32
                )
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.pbkdf2DeriveFailed))
            #expect(record.category == OpalDiagnostics.Category.keyDerivation)
            #expect(record.level == .error)
            #expect(field("operation", in: record)?.value == "pbkdf2_derive")
            #expect(field("error_code", in: record)?.value == "invalid_iteration_count")
            #expect(record.fields.contains { $0.value.contains("wallet-password-material") } == false)
        }
    }

    @Test("PBKDF2 default length diagnostics report the effective byte count")
    func pbkdf2DefaultLengthDiagnosticsReportEffectiveByteCount() throws {
        try withDiagnosticsCapture {
            let salt = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8))

            let derivedKey = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                password: Data("wallet-password-material".utf8),
                salt: salt,
                iterationCount: 1,
                derivedKeyLength: nil
            )

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.pbkdf2DeriveSucceeded))
            #expect(derivedKey.rawRepresentation.count == 64)
            #expect(field("requested_derived_key_byte_count", in: record)?.value == "64")
            #expect(field("has_explicit_derived_key_length", in: record)?.value == "false")
            #expect(field("output_byte_count", in: record)?.value == "64")
        }
    }

    @Test("Mnemonic seed derivation records public-safe diagnostics")
    func mnemonicSeedDerivationRecordsPublicSafeDiagnostics() throws {
        try withDiagnosticsCapture {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            let mnemonic = try OpalCrypto.Key.Mnemonic(phrase: phrase, language: .english)

            OpalDiagnostics.clearRecentRecords()

            let seed = try mnemonic.deriveSeed(passphrase: "TREZOR")

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.mnemonicSeedDeriveSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: record)?.value == "mnemonic_seed_derive")
            #expect(field("word_count", in: record)?.value == "12")
            #expect(field("language", in: record)?.value == "english")
            #expect(field("output_byte_count", in: record)?.value == String(seed.rawRepresentation.count))
            #expect(record.fields.contains { $0.value.contains("abandon") } == false)
            #expect(record.fields.contains { $0.value.contains("TREZOR") } == false)
        }
    }

    @Test("Tweak-add failures record stable error codes")
    func tweakAddFailuresRecordStableErrorCodes() throws {
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
            #expect(field("error_code", in: record)?.value == "invalid_derived_key")
            #expect(record.fields.contains { $0.value.contains("FFFFFFFF") } == false)
        }
    }

    @Test("Public-key derivation and tweak-add avoid nested parse diagnostics")
    func publicKeyDerivationAndTweakAddAvoidNestedParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(23)
            let tweak = try OpalCryptoTestSupport.makeScalar(1)

            OpalDiagnostics.clearRecentRecords()

            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyDeriveSucceeded) != nil)
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseSucceeded) == nil)

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Secp256k1.tweakAddPublicKey(publicKey, tweak: tweak)

            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyTweakAddSucceeded) != nil)
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseSucceeded) == nil)
        }
    }

    @Test("Uncompressed verification-key parsing records normalized output length")
    func uncompressedVerificationKeyParsingRecordsNormalizedOutputLength() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(11)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

            OpalDiagnostics.clearRecentRecords()

            let verificationKey = try OpalCrypto.Signature.VerificationKey(
                rawRepresentation: publicKey.uncompressedRepresentation
            )

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.verificationKeyParseSucceeded))
            #expect(verificationKey.rawRepresentation.count == 33)
            #expect(field("input_byte_count", in: record)?.value == "65")
            #expect(field("output_byte_count", in: record)?.value == "33")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseSucceeded) == nil)
        }
    }

    @Test("Shared-secret raw parsing records parse diagnostics")
    func sharedSecretRawParsingRecordsParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let validSecret = Data(repeating: 0x01, count: 32)

            _ = try OpalCrypto.Secp256k1.SharedSecret(rawRepresentation: validSecret)

            let successRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretParseSucceeded))
            #expect(successRecord.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: successRecord)?.value == "shared_secret_parse")
            #expect(field("input_byte_count", in: successRecord)?.value == "32")
            #expect(field("output_byte_count", in: successRecord)?.value == "32")

            OpalDiagnostics.clearRecentRecords()

            #expect(throws: OpalCrypto.Secp256k1.Error.self) {
                _ = try OpalCrypto.Secp256k1.SharedSecret(
                    rawRepresentation: Data(repeating: 0x01, count: 31)
                )
            }

            let failureRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretParseFailed))
            #expect(failureRecord.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: failureRecord)?.value == "shared_secret_parse")
            #expect(field("input_byte_count", in: failureRecord)?.value == "31")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretDeriveFailed) == nil)
        }
    }

    @Test("Shared-secret derivation does not emit nested parse diagnostics")
    func sharedSecretDerivationDoesNotEmitNestedParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(19)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Secp256k1.deriveSharedSecret(
                privateKey: privateKey,
                publicKey: publicKey
            )

            #expect(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretDeriveSucceeded) != nil)
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.sharedSecretParseSucceeded) == nil)
        }
    }

    @Test("Extended-key validated accessors do not emit parse diagnostics")
    func extendedKeyValidatedAccessorsDoNotEmitParseDiagnostics() throws {
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
        }
    }

    @Test("Private-key decryption result does not emit symmetric-key parse diagnostics")
    func privateKeyDecryptionResultDoesNotEmitSymmetricKeyParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(13)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            let ciphertext = try OpalCrypto.Communication.encrypt(
                message: Data("diagnostics-decrypt-success".utf8),
                recipientPublicKey: publicKey,
                paddedPlaintextLength: 32
            )

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Communication.decrypt(ciphertext, privateKey: privateKey)

            #expect(diagnosticRecord(named: OpalDiagnostics.Event.communicationDecryptSucceeded) != nil)
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.communicationSymmetricKeyParseSucceeded) == nil)
        }
    }

    @Test("Communication encrypt default padding diagnostics report resolved length")
    func communicationEncryptDefaultPaddingDiagnosticsReportResolvedLength() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(31)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Communication.encrypt(
                message: Data("abc".utf8),
                recipientPublicKey: publicKey
            )

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.communicationEncryptSucceeded))
            #expect(field("plaintext_byte_count", in: record)?.value == "3")
            #expect(field("padded_plaintext_length", in: record)?.value == "16")
            #expect(field("has_explicit_padding", in: record)?.value == "false")
        }
    }

    @Test("Communication encrypt invalid explicit padding diagnostics report requested length")
    func communicationEncryptInvalidExplicitPaddingDiagnosticsReportRequestedLength() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(37)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)

            OpalDiagnostics.clearRecentRecords()

            #expect(throws: OpalCrypto.Communication.Error.invalidPaddedPlaintextLength(minimum: 8, actual: 5)) {
                _ = try OpalCrypto.Communication.encrypt(
                    message: Data("abcd".utf8),
                    recipientPublicKey: publicKey,
                    paddedPlaintextLength: 5
                )
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.communicationEncryptFailed))
            #expect(field("padded_plaintext_length", in: record)?.value == "5")
            #expect(field("has_explicit_padding", in: record)?.value == "true")
            #expect(field("error_code", in: record)?.value == "invalid_padded_plaintext_length")
        }
    }

    @Test("WIF parsing does not emit nested private-key parse diagnostics")
    func wifParsingDoesNotEmitNestedPrivateKeyParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(17)
            let serialized = try OpalCrypto.Key.WIF(privateKey: privateKey).serialize()

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Key.WIF(serialized)

            #expect(diagnosticRecord(named: OpalDiagnostics.Event.wifParseSucceeded) != nil)
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.privateKeyParseSucceeded) == nil)
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

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.communicationDecryptFailed))
            #expect(record.category == OpalDiagnostics.Category.communication)
            #expect(record.level == .error)
            #expect(field("operation", in: record)?.value == "decrypt")
            #expect(field("mode", in: record)?.value == "private_key")
            #expect(field("ciphertext_byte_count", in: record)?.value == String(tamperedCiphertextData.count))
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
            #expect(events.contains(OpalDiagnostics.Event.base58DecodeFailed))
            #expect(events.contains(OpalDiagnostics.Event.base58CheckDecodeFailed))
            #expect(events.contains(OpalDiagnostics.Event.wifParseFailed))
            #expect(events.contains(OpalDiagnostics.Event(rawValue: "opalcrypto.base.filtered")) == false)

            let base58Record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.base58DecodeFailed))
            #expect(field("error_code", in: base58Record)?.value == "invalid_base58")

            let encodingRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.base58CheckDecodeFailed))
            #expect(encodingRecord.category == OpalDiagnostics.Category.encoding)
            #expect(field("input_character_count", in: encodingRecord)?.value == "1")
        }
    }

    private static let diagnosticsConfiguration = OpalDiagnostics.Configuration(
        minimumLevel: .debug,
        categoryFilter: .enabledIncludingSubcategories([OpalDiagnostics.Category.crypto]),
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
