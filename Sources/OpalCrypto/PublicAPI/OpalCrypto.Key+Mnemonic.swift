// OpalCrypto.Key+Mnemonic.swift

import Foundation

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
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.mnemonicParseFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.mnemonicParseSucceeded,
                category: OpalCryptoDiagnostics.Category.key,
                fields: fields + [
                    OpalCryptoDiagnostics.publicField("resolved_language", self.language.rawValue),
                    OpalCryptoDiagnostics.publicField("resolved_word_count", self.words.count)
                ]
            )
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
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.mnemonicParseFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.mnemonicParseSucceeded,
                category: OpalCryptoDiagnostics.Category.key,
                fields: fields + [
                    OpalCryptoDiagnostics.publicField("resolved_language", self.language.rawValue),
                    OpalCryptoDiagnostics.publicField("resolved_word_count", self.words.count)
                ]
            )
        }

        public static func generate(
            length: Length,
            language: Word.Language
        ) throws -> Mnemonic {
            let fields = [
                OpalCryptoDiagnostics.operationField("mnemonic_generate"),
                OpalCryptoDiagnostics.publicField("word_count", length.rawValue),
                OpalCryptoDiagnostics.publicField("language", language.rawValue)
            ]
            do {
                let mnemonic = try generate(
                    length: length,
                    language: language,
                    makeEntropyBytes: SecureRandomByteGenerationModel.makeBytes(count:)
                )
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.mnemonicGenerateSucceeded,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields
                )
                return mnemonic
            } catch let error as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.mnemonicGenerateFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
        }

        private static func parseFields(
            wordCount: Int,
            language: Word.Language?
        ) -> [OpalCryptoDiagnostics.Field] {
            [
                OpalCryptoDiagnostics.operationField("mnemonic_parse"),
                OpalCryptoDiagnostics.formatField("bip39"),
                OpalCryptoDiagnostics.publicField("word_count", wordCount),
                OpalCryptoDiagnostics.publicField("language", language?.rawValue ?? "auto")
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
            } catch let error as SecureRandomByteGenerationModel.Error {
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
            try OpalCrypto.Key.Seed(
                rawRepresentation: MnemonicCodecModel.deriveSeed(
                    phrase: phrase,
                    passphrase: passphrase
                )
            )
        }

        internal init(parsed: MnemonicCodecModel.ParsedMnemonic) {
            self.words = parsed.words.map(Word.init)
            self.length = parsed.length
            self.language = parsed.language
        }
    }
}
