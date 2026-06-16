// DiagnosticsIntegrationValidator~Mnemonic.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
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
            #expect(field("format", in: record)?.value == "bip39")
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

    @Test("Mnemonic parsing records public-safe entropy length")
    func validateMnemonicParsingRecordsPublicSafeEntropyLength() throws {
        try withDiagnosticsCapture {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

            _ = try OpalCrypto.Key.Mnemonic(phrase: phrase, language: .english)

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.mnemonicParseSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(record.level == .debug)
            #expect(field("operation", in: record)?.value == "mnemonic_parse")
            #expect(field("format", in: record)?.value == "bip39")
            expectPublicField("word_count", in: record, equals: "12")
            expectPublicField("language", in: record, equals: "english")
            expectPublicField("resolved_language", in: record, equals: "english")
            expectPublicField("resolved_word_count", in: record, equals: "12")
            expectPublicField("entropy_byte_count", in: record, equals: "16")
            #expect(field("phrase", in: record) == nil)
            #expect(field("mnemonic", in: record) == nil)
            #expect(record.fields.contains { $0.value.contains("abandon") } == false)
        }
    }

    @Test("Mnemonic generation records public-safe entropy length")
    func validateMnemonicGenerationRecordsPublicSafeEntropyLength() throws {
        try withDiagnosticsCapture {
            let mnemonic = try OpalCrypto.Key.Mnemonic.generate(
                length: .words12,
                language: .english
            )

            let record = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.mnemonicGenerateSucceeded)
            )
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(record.level == .debug)
            #expect(field("operation", in: record)?.value == "mnemonic_generate")
            #expect(field("format", in: record)?.value == "bip39")
            expectPublicField("word_count", in: record, equals: "12")
            expectPublicField("language", in: record, equals: "english")
            expectPublicField("entropy_byte_count", in: record, equals: "16")
            #expect(field("entropy", in: record) == nil)
            #expect(field("phrase", in: record) == nil)
            #expect(field("mnemonic", in: record) == nil)
            #expect(mnemonic.words.count == 12)
        }
    }
}
