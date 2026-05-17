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
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.mnemonicParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
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
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.mnemonicParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
            recordParseSucceeded(fields: fields)
        }

        private func recordParseSucceeded(
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.mnemonicParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicParseSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.publicField("resolved_language", self.language.rawValue),
                    OpalDiagnostics.Field.publicField("resolved_word_count", self.words.count)
                ]
            )
        }

        public static func generate(
            length: Length,
            language: Word.Language
        ) throws -> Mnemonic {
            let fields = [
                OpalDiagnostics.Field.operationField("mnemonic_generate"),
                OpalDiagnostics.Field.publicField("word_count", length.rawValue),
                OpalDiagnostics.Field.publicField("language", language.rawValue)
            ]
            do {
                let mnemonic = try generate(
                    length: length,
                    language: language,
                    makeEntropyBytes: SecureRandomByteGenerator.makeBytes(count:)
                )
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.mnemonicGenerateSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicGenerateSucceeded),
                    fields: fields
                )
                return mnemonic
            } catch let error as Error {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.mnemonicGenerateFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicGenerateFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
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

        internal static func generate(
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
            let fields = [
                OpalDiagnostics.Field.operationField("mnemonic_seed_derive"),
                OpalDiagnostics.Field.publicField("word_count", words.count),
                OpalDiagnostics.Field.publicField("language", language.rawValue)
            ]
            do {
                let seed = try OpalCrypto.Key.Seed(
                    rawRepresentation: MnemonicCodecModel.deriveSeed(
                        phrase: phrase,
                        passphrase: passphrase
                    )
                )
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.mnemonicSeedDeriveSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicSeedDeriveSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.outputLengthField(seed.rawRepresentation.count)
                    ]
                )
                return seed
            } catch {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.mnemonicSeedDeriveFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicSeedDeriveFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
        }

        internal init(parsed: MnemonicCodecModel.ParsedMnemonic) {
            self.words = parsed.words.map(Word.init)
            self.length = parsed.length
            self.language = parsed.language
        }
    }
}
