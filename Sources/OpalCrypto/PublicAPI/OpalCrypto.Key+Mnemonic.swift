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
            let parsed = try MnemonicCodecModel.parse(phrase: phrase, language: language)
            self.init(parsed: parsed)
        }

        public init(words: [Word], language: Word.Language? = nil) throws {
            let parsed = try MnemonicCodecModel.parse(
                words: words.map(\.text),
                language: language
            )
            self.init(parsed: parsed)
        }

        public static func generate(
            length: Length,
            language: Word.Language
        ) throws -> Mnemonic {
            try generate(
                length: length,
                language: language,
                makeEntropyBytes: SecureRandomByteGenerationModel.makeBytes(count:)
            )
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
