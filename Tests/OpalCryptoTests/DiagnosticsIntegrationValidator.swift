// DiagnosticsIntegrationValidator.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

@Suite(.serialized)
struct DiagnosticsIntegrationValidator {
    @Test("OpalDiagnostics catalog exposes stable typed values")
    func validateOpalDiagnosticsCatalogExposesStableTypedValues() {
        let category: OpalDiagnostics.Category = .key
        let event: OpalDiagnostics.Event = .wifParseFailed
        let level: OpalDiagnostics.Level = .error

        #expect(category.rawValue == "crypto.key")
        #expect(event.rawValue == "opalcrypto.key.wif.parse.failed")
        #expect(level == .error)
        #expect(OpalDiagnostics.Level.opalCryptoDefault(for: event) == .error)
        #expect(OpalDiagnostics.Level.opalCryptoDefault(for: .wifParseSucceeded) == .debug)
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
    func validateDefaultOpalDiagnosticsConfigurationKeepsOpalCryptoSilent() throws {
        try OpalDiagnostics.withConfiguration(.init()) {
            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: Data(repeating: 0x01, count: 32)
            )

            #expect(OpalDiagnostics.recentRecords.isEmpty)
        }
    }

    @Test("OpalDiagnostics trace wrapper propagates current trace into records")
    func validateOpalDiagnosticsTraceWrapperPropagatesCurrentTraceIntoRecords() throws {
        try withDiagnosticsCapture {
            let traceID = OpalDiagnostics.TraceID(rawValue: "wallet-diagnostics-flow")

            try OpalDiagnostics.withTraceID(traceID) {
                _ = try OpalCrypto.Secp256k1.PrivateKey(
                    rawRepresentation: Data(repeating: 0x01, count: 32)
                )
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.privateKeyParseSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(record.traceID == traceID)
            #expect(field("operation", in: record)?.value == "private_key_parse")
            #expect(field("input_byte_count", in: record)?.value == "32")
            #expect(field("output_byte_count", in: record)?.value == "32")
            #expect(OpalDiagnostics.currentTraceID == nil)
        }
    }

    @Test("Private-key generation avoids nested parse diagnostics")
    func validatePrivateKeyGenerationAvoidsNestedParseDiagnostics() throws {
        try withDiagnosticsCapture {
            _ = try OpalCrypto.Secp256k1.PrivateKey.generate()

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.privateKeyGenerateSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: record)?.value == "private_key_generate")
            #expect(field("output_byte_count", in: record)?.value == "32")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.privateKeyParseSucceeded) == nil)
        }
    }

    @Test("Blind-signature signer preparation avoids nested public-key parse diagnostics")
    func validateBlindSignatureSignerPreparationAvoidsNestedPublicKeyParseDiagnostics() throws {
        try withDiagnosticsCapture {
            _ = try OpalCrypto.BlindSignature.Signer()

            let record = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.blindSignatureSignerPrepareSucceeded)
            )
            #expect(record.category == OpalDiagnostics.Category.blindSignature)
            #expect(field("operation", in: record)?.value == "signer_prepare")
            #expect(field("nonce_point_byte_count", in: record)?.value == "33")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseSucceeded) == nil)
        }
    }

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
    func validateHashingFacadeRecordsPublicSafeBoundaryDiagnostics() throws {
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

            OpalDiagnostics.clearRecentRecords()

            let key = Data("diagnostics-hmac-key".utf8)
            let mac = OpalCrypto.Hashing.hmacSHA256(data: payload, key: key)

            let hmacRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.hmacSHA256Succeeded))
            #expect(hmacRecord.category == OpalDiagnostics.Category.hashing)
            #expect(hmacRecord.level == .debug)
            #expect(field("operation", in: hmacRecord)?.value == "hash")
            #expect(field("algorithm", in: hmacRecord)?.value == "hmac_sha256")
            #expect(field("input_byte_count", in: hmacRecord)?.value == String(payload.count))
            #expect(field("output_byte_count", in: hmacRecord)?.value == String(mac.count))
            expectPublicField("key_byte_count", in: hmacRecord, equals: String(key.count))
            #expect(field("key", in: hmacRecord) == nil)
            #expect(hmacRecord.fields.contains { $0.value.contains("diagnostics-hash-payload") } == false)
            #expect(hmacRecord.fields.contains { $0.value.contains("diagnostics-hmac-key") } == false)
        }
    }

    @Test("PBKDF2 failures record stable public error codes without password material")
    func validatePBKDF2FailuresRecordStablePublicErrorCodesWithoutPasswordMaterial() throws {
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
            expectPublicField("password_byte_count", in: record, equals: String(password.count))
            #expect(field("salt_byte_count", in: record)?.value == String(salt.rawRepresentation.count))
            #expect(field("iteration_count", in: record)?.value == "0")
            #expect(field("requested_derived_key_byte_count", in: record)?.value == "32")
            #expect(field("has_explicit_derived_key_length", in: record)?.value == "true")
            #expect(field("error_code", in: record)?.value == "invalid_iteration_count")
            #expect(field("password", in: record) == nil)
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
            expectPublicField("password_byte_count", in: record, equals: "24")
            #expect(field("requested_derived_key_byte_count", in: record)?.value == "64")
            #expect(field("has_explicit_derived_key_length", in: record)?.value == "false")
            #expect(field("output_byte_count", in: record)?.value == "64")
        }
    }

    @Test("Mnemonic seed derivation records public-safe diagnostics")
    func validateMnemonicSeedDerivationRecordsPublicSafeDiagnostics() throws {
        try withDiagnosticsCapture {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            let mnemonic = try OpalCrypto.Key.Mnemonic(phrase: phrase, language: .english)

            OpalDiagnostics.clearRecentRecords()

            let seed = try mnemonic.deriveSeed(passphrase: "TREZOR")

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.mnemonicSeedDeriveSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(record.level == .debug)
            #expect(field("operation", in: record)?.value == "mnemonic_seed_derive")
            #expect(field("word_count", in: record)?.value == "12")
            #expect(field("language", in: record)?.value == "english")
            expectPublicField("passphrase_byte_count", in: record, equals: "6")
            #expect(field("phrase", in: record) == nil)
            #expect(field("mnemonic", in: record) == nil)
            #expect(field("passphrase", in: record) == nil)
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

            let deriveRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyDeriveSucceeded))
            #expect(deriveRecord.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: deriveRecord)?.value == "public_key_derive")
            #expect(field("algorithm", in: deriveRecord)?.value == "secp256k1")
            #expect(field("output_byte_count", in: deriveRecord)?.value == "33")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyParseSucceeded) == nil)

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Secp256k1.tweakAddPublicKey(publicKey, tweak: tweak)

            let tweakRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.publicKeyTweakAddSucceeded))
            #expect(tweakRecord.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: tweakRecord)?.value == "public_key_tweak_add")
            #expect(field("algorithm", in: tweakRecord)?.value == "secp256k1")
            #expect(field("output_byte_count", in: tweakRecord)?.value == "33")
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
    func validatePrivateKeyDecryptionResultDoesNotEmitSymmetricKeyParseDiagnostics() throws {
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

    @Test("Pedersen point combination does not emit commitment-parse diagnostics")
    func validatePedersenPointCombinationDoesNotEmitCommitmentParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let alternateBasePrivateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(31)
            let alternateBasePoint = try OpalCrypto.Secp256k1.derivePublicKey(from: alternateBasePrivateKey)
            let setup = try OpalCrypto.Pedersen.Setup(alternateBasePoint: alternateBasePoint)
            let firstCommitment = try setup.commit(
                amount: 4,
                nonce: OpalCrypto.Pedersen.Nonce(rawRepresentation: OpalCryptoTestSupport.makePrivateKey(3))
            )
            let secondCommitment = try setup.commit(
                amount: 9,
                nonce: OpalCrypto.Pedersen.Nonce(rawRepresentation: OpalCryptoTestSupport.makePrivateKey(5))
            )

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Pedersen.Setup.addPoints([
                firstCommitment.point,
                secondCommitment.point
            ])

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.pedersenCombineSucceeded))
            #expect(record.category == OpalDiagnostics.Category.pedersen)
            #expect(field("operation", in: record)?.value == "combine_points")
            #expect(field("point_count", in: record)?.value == "2")
            #expect(field("commitment_byte_count", in: record)?.value == "65")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.pedersenCommitmentParseSucceeded) == nil)
        }
    }

    @Test("Symmetric-key communication decrypt records public-safe key length")
    func validateSymmetricKeyCommunicationDecryptRecordsPublicSafeKeyLength() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(29)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            let ciphertext = try OpalCrypto.Communication.encrypt(
                message: Data("symmetric-diagnostics".utf8),
                recipientPublicKey: publicKey
            )
            let decrypted = try OpalCrypto.Communication.decrypt(ciphertext, privateKey: privateKey)

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Communication.decrypt(ciphertext, symmetricKey: decrypted.symmetricKey)

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

    @Test("Communication encrypt default padding diagnostics report resolved length")
    func validateCommunicationEncryptDefaultPaddingDiagnosticsReportResolvedLength() throws {
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
    func validateCommunicationEncryptInvalidExplicitPaddingDiagnosticsReportRequestedLength() throws {
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
    func validateWIFParsingDoesNotEmitNestedPrivateKeyParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(17)
            let serialized = try OpalCrypto.Key.WIF(privateKey: privateKey).serialize()

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Key.WIF(serialized)

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.wifParseSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: record)?.value == "wif_parse")
            #expect(field("format", in: record)?.value == "wif")
            #expect(field("private_key_byte_count", in: record)?.value == "32")
            #expect(field("private_key_byte_count", in: record)?.privacy == .public)
            #expect(field("is_compressed", in: record)?.value == "true")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.privateKeyParseSucceeded) == nil)
        }
    }

    @Test("WIF serialization records public-safe private-key length")
    func validateWIFSerializationRecordsPublicSafePrivateKeyLength() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(19)

            _ = try OpalCrypto.Key.WIF(privateKey: privateKey, isCompressed: false).serialize()

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.wifSerializeSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: record)?.value == "wif_serialize")
            #expect(field("format", in: record)?.value == "wif")
            #expect(field("private_key_byte_count", in: record)?.value == "32")
            #expect(field("private_key_byte_count", in: record)?.privacy == .public)
            #expect(field("is_compressed", in: record)?.value == "false")
            #expect(field("output_character_count", in: record)?.value == "51")
        }
    }

    @Test("Communication decrypt failure records no key or payload material")
    func validateCommunicationDecryptFailureRecordsNoKeyOrPayloadMaterial() throws {
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

    private func withDiagnosticsCapture<Success>(_ operation: () async throws -> Success) async rethrows -> Success {
        try await OpalDiagnostics.withConfiguration(Self.diagnosticsConfiguration) {
            OpalDiagnostics.clearRecentRecords()
            return try await operation()
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

    private func expectPublicField(
        _ name: String,
        in record: OpalDiagnostics.Record,
        equals expectedValue: String
    ) {
        let diagnosticField = field(name, in: record)
        #expect(diagnosticField?.value == expectedValue)
        #expect(diagnosticField?.privacy == .public)
    }
}
