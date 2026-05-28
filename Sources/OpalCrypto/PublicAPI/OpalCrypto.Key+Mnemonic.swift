// OpalCrypto.Key+Mnemonic.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Key {
    public struct Mnemonic: Sendable, Equatable {

        public let words: [Word]
        public let length: Length
        public let language: Word.Language

        public var phrase: String {
            words.map(\.text).joined(separator: " ")
        }

        public init(phrase: String, language: Word.Language? = nil) throws {
            let fields = Self.parseFields(
                wordCount: phrase.split(whereSeparator: \.isWhitespace).count,
                language: language
            )
            do {
                let parsed = try MnemonicCodecModel.parse(phrase: phrase, language: language)
                self.init(parsed: parsed)
            } catch let error as Error {
                Self.recordParseFailed(error, fields: fields)
                throw error
            }
            recordParseSucceeded(fields: fields)
        }

        public init(words: [Word], language: Word.Language? = nil) throws {
            let fields = Self.parseFields(wordCount: words.count, language: language)
            do {
                let parsed = try MnemonicCodecModel.parse(
                    words: words.map(\.text),
                    language: language
                )
                self.init(parsed: parsed)
            } catch let error as Error {
                Self.recordParseFailed(error, fields: fields)
                throw error
            }
            recordParseSucceeded(fields: fields)
        }

        private static func recordParseFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.mnemonicParseFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicParseFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }

        private func recordParseSucceeded(
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.mnemonicParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicParseSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.publicField("resolved_language", self.language.rawValue),
                    OpalDiagnostics.Field.publicField("resolved_word_count", self.words.count),
                    OpalDiagnostics.Field.publicField("entropy_byte_count", self.length.entropyByteCount)
                ]
            )
        }

        public static func generate(
            length: Length,
            language: Word.Language
        ) throws -> Mnemonic {
            let fields = Self.generateFields(length: length, language: language)
            do {
                let mnemonic = try makeGeneratedMnemonic(
                    length: length,
                    language: language,
                    makeEntropyBytes: SecureRandomByteGenerator.makeBytes(count:)
                )
                Self.recordGenerateSucceeded(fields: fields)
                return mnemonic
            } catch let error as Error {
                Self.recordGenerateFailed(error, fields: fields)
                throw error
            }
        }

        private static func generateFields(
            length: Length,
            language: Word.Language
        ) -> [OpalDiagnostics.Field] {
            [
                OpalDiagnostics.Field.operationField("mnemonic_generate"),
                OpalDiagnostics.Field.formatField("bip39"),
                OpalDiagnostics.Field.publicField("word_count", length.rawValue),
                OpalDiagnostics.Field.publicField("language", language.rawValue),
                OpalDiagnostics.Field.publicField("entropy_byte_count", length.entropyByteCount)
            ]
        }

        private static func recordGenerateSucceeded(
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.mnemonicGenerateSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicGenerateSucceeded),
                fields: fields
            )
        }

        private static func recordGenerateFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.mnemonicGenerateFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicGenerateFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }

        private static func parseFields(
            wordCount: Int,
            language: Word.Language?
        ) -> [OpalDiagnostics.Field] {
            [
                OpalDiagnostics.Field.operationField("mnemonic_parse"),
                OpalDiagnostics.Field.formatField("bip39"),
                OpalDiagnostics.Field.publicField("word_count", wordCount),
                OpalDiagnostics.Field.publicField("language", language?.rawValue ?? "auto")
            ]
        }

        internal static func makeGeneratedMnemonic(
            length: Length,
            language: Word.Language,
            makeEntropyBytes: (Int) throws -> [UInt8]
        ) throws -> Mnemonic {
            let entropyBytes: [UInt8]
            do {
                entropyBytes = try makeEntropyBytes(length.entropyByteCount)
            } catch let error as SecureRandomByteGenerator.Error {
                switch error {
                case .failed(let status):
                    throw Error.randomGenerationFailed(status: status)
                }
            }

            let entropy = Data(entropyBytes)
            return try Mnemonic(
                parsed: MnemonicCodecModel.makeMnemonic(entropy: entropy, language: language)
            )
        }

        public func deriveSeed(passphrase: String = "") throws -> OpalCrypto.Key.Seed {
            let fields = seedDeriveFields(passphrase: passphrase)
            do {
                let seed = try OpalCrypto.Key.Seed(
                    rawRepresentation: MnemonicCodecModel.deriveSeed(
                        phrase: phrase,
                        passphrase: passphrase
                    )
                )
                Self.recordSeedDeriveSucceeded(seed: seed, fields: fields)
                return seed
            } catch {
                Self.recordSeedDeriveFailed(error, fields: fields)
                throw error
            }
        }

        private func seedDeriveFields(passphrase: String) -> [OpalDiagnostics.Field] {
            [
                OpalDiagnostics.Field.operationField("mnemonic_seed_derive"),
                OpalDiagnostics.Field.formatField("bip39"),
                OpalDiagnostics.Field.publicField("word_count", words.count),
                OpalDiagnostics.Field.publicField("language", language.rawValue),
                OpalDiagnostics.Field.publicField("passphrase_byte_count", passphrase.utf8.count)
            ]
        }

        private static func recordSeedDeriveSucceeded(
            seed: OpalCrypto.Key.Seed,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.mnemonicSeedDeriveSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicSeedDeriveSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(seed.rawRepresentation.count)
                ]
            )
        }

        private static func recordSeedDeriveFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.mnemonicSeedDeriveFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicSeedDeriveFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }

        internal init(parsed: MnemonicCodecModel.ParsedMnemonic) {
            self.words = parsed.words.map(Word.init)
            self.length = parsed.length
            self.language = parsed.language
        }
    }
}
