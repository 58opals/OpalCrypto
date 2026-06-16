// OpalCrypto.Key+Mnemonic.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Key {
    /// A BIP-39 mnemonic phrase.
    ///
    /// `Mnemonic` is secret-bearing key material. Its words and phrase can recreate seed material and should only cross explicit secret-access or signing/authoring boundaries.
    public struct Mnemonic: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {

        /// The normalized BIP-39 words.
        ///
        /// This array is secret-bearing in aggregate and should be handled with the same care as the full phrase.
        public let words: [Word]
        /// The BIP-39 mnemonic length.
        public let length: Length
        /// The resolved BIP-39 language.
        public let language: Word.Language

        /// The normalized mnemonic phrase.
        ///
        /// The returned string is secret-bearing and can derive the same seed material as `words`.
        public var phrase: String {
            words.map(\.text).joined(separator: " ")
        }

        /// A redacted description that never includes mnemonic words or the full phrase.
        public var description: String {
            "OpalCrypto.Key.Mnemonic(redacted, wordCount: \(words.count), language: \(language.rawValue))"
        }

        /// A redacted debug description that never includes mnemonic words or the full phrase.
        public var debugDescription: String {
            description
        }

        /// Creates a mnemonic from a BIP-39 phrase.
        ///
        /// `phrase` is secret-bearing input. Diagnostics record only public-safe metadata such as word count, language, and error code.
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

        /// Creates a mnemonic from normalized or normalizable BIP-39 words.
        ///
        /// The word sequence is secret-bearing in aggregate. Diagnostics record only public-safe metadata such as word count, language, and error code.
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

        /// Generates a new BIP-39 mnemonic using secure random entropy.
        ///
        /// The returned mnemonic is secret-bearing. Diagnostics record only public-safe metadata such as word count, language, and entropy byte count.
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
        internal init(parsed: MnemonicCodecModel.ParsedMnemonic) {
            self.words = parsed.words.map(Word.init)
            self.length = parsed.length
            self.language = parsed.language
        }
    }
}
