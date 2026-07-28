// DiagnosticsIntegrationValidator~Catalog.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
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
                _ = try Base58CheckCodec.decode(
                    "0",
                    minimumPayloadLength: -4,
                    maximumPayloadLength: 78
                )
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.base58CheckDecodeFailed))
            #expect(field("minimum_payload_length", in: record)?.value == "0")

            OpalDiagnostics.clearRecentRecords()

            let validBase58Check = Base58CheckCodec.encode(payload: Data([0x01]))
            let invalidChecksum = String(validBase58Check.dropLast()) + (validBase58Check.last == "1" ? "2" : "1")
            #expect(throws: Base58CheckCodec.Error.invalidChecksum) {
                _ = try Base58CheckCodec.decode(
                    invalidChecksum,
                    minimumPayloadLength: -4,
                    maximumPayloadLength: 78
                )
            }

            let checksumRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.base58CheckDecodeFailed))
            #expect(field("minimum_payload_length", in: checksumRecord)?.value == "0")
        }
    }

    @Test("Base32 decode diagnostics report format and mode")
    func validateBase32DecodeDiagnosticsReportFormatAndMode() throws {
        try withDiagnosticsCapture {
            #expect(throws: OpalCrypto.Encoding.Error.invalidCharacterFound) {
                _ = try OpalCrypto.Encoding.decodeBase32Values("!")
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.base32DecodeFailed))
            #expect(record.category == OpalDiagnostics.Category.encoding)
            #expect(record.level == .error)
            #expect(field("operation", in: record)?.value == "base32_decode")
            #expect(field("format", in: record)?.value == "base32")
            expectPublicField("mode", in: record, equals: "five_bit_values")
            expectPublicField("input_character_count", in: record, equals: "1")
            #expect(field("error_code", in: record)?.value == "invalid_character_found")
            #expect(field("input", in: record) == nil)
        }
    }

    @Test("Encoding limit diagnostics use stable facade error codes")
    func validateEncodingLimitDiagnosticsUseStableFacadeErrorCodes() throws {
        let base58ErrorCode = try #require(
            OpalDiagnostics.Field.errorFields(
                OpalCrypto.Encoding.Base58DecodingError
                    .decodedDataExceedsMaximumByteCount(maximum: 32)
            )
            .first { $0.name == "error_code" }?
            .value
        )
        let base32ErrorCode = try #require(
            OpalDiagnostics.Field.errorFields(
                OpalCrypto.Encoding.Error.invalidMaximumDecodedByteCount(actual: -1)
            )
            .first { $0.name == "error_code" }?
            .value
        )

        #expect(base58ErrorCode == "decoded_data_exceeds_maximum_byte_count")
        #expect(base32ErrorCode == "invalid_maximum_decoded_byte_count")
    }

    @Test("Mnemonic resource-limit diagnostics use stable facade error codes")
    func validateMnemonicResourceLimitDiagnosticsUseStableFacadeErrorCodes() throws {
        let wordCountErrorCode = try #require(
            OpalDiagnostics.Field.errorFields(
                OpalCrypto.Key.Mnemonic.Error.wordCountExceedsMaximum(maximum: 24)
            )
            .first { $0.name == "error_code" }?
            .value
        )
        let phraseByteCountErrorCode = try #require(
            OpalDiagnostics.Field.errorFields(
                OpalCrypto.Key.Mnemonic.Error.phraseByteCountExceedsMaximum(
                    maximum: 8_192,
                    actual: 8_193
                )
            )
            .first { $0.name == "error_code" }?
            .value
        )

        #expect(wordCountErrorCode == "word_count_exceeds_maximum")
        #expect(phraseByteCountErrorCode == "phrase_byte_count_exceeds_maximum")
    }

    @Test("Fixed-format payload-limit diagnostics use a stable facade error code")
    func validateFixedFormatPayloadLimitDiagnosticsUseStableFacadeErrorCode() throws {
        let errorCode = try #require(
            OpalDiagnostics.Field.errorFields(
                OpalCrypto.Key.WIF.Error.payloadLengthExceedsMaximum(maximum: 34)
            )
            .first { $0.name == "error_code" }?
            .value
        )

        #expect(errorCode == "payload_length_exceeds_maximum")
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
            let traceID = OpalDiagnostics.TraceID(publicValue: "wallet-diagnostics-flow")

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
            #expect(field("format", in: record)?.value == "raw")
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
}
