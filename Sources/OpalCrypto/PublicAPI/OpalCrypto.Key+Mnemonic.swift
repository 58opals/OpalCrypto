// OpalCrypto.Key+Mnemonic.swift

import Foundation

extension OpalCrypto.Key {
    public struct Mnemonic: Sendable, Equatable {
        public enum Length: Int, CaseIterable, Sendable {
            case words12 = 12
            case words15 = 15
            case words18 = 18
            case words21 = 21
            case words24 = 24
        }

        public struct Word: Sendable, Hashable, LosslessStringConvertible {
            public enum Language: String, CaseIterable, Sendable {
                case english
                case korean
            }

            public let text: String

            public init(_ description: String) {
                self.text = MnemonicCodecModel.normalizeWord(description)
            }

            public var description: String {
                text
            }
        }

        public struct WordList: Sendable, Equatable {
            public let language: Word.Language
            public let words: [Word]

            internal let indexLookup: [String: Int]

            public var count: Int {
                words.count
            }

            public subscript(index: Int) -> Word {
                words[index]
            }

            public static func load(_ language: Word.Language) throws -> WordList {
                let wordList = try MnemonicWordListRepository.load(language)
                return WordList(language: language, wordList: wordList)
            }

            public func contains(_ word: Word) -> Bool {
                indexLookup[word.text] != nil
            }

            public func index(of word: Word) -> Int? {
                indexLookup[word.text]
            }

            internal init(
                language: Word.Language,
                wordList: MnemonicWordListRepository.WordListData
            ) {
                self.language = language
                self.words = wordList.words.map(Word.init)
                self.indexLookup = wordList.indexLookup
            }
        }

        public enum Error: Swift.Error, Equatable {
            case invalidWordCount(actual: Int)
            case invalidEntropyLength(actual: Int)
            case invalidWord(String)
            case invalidChecksum
            case ambiguousLanguage
            case wordListResourceMissing(language: Word.Language)
            case invalidWordList(language: Word.Language, actualCount: Int)
        }

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
            let entropy = Data(try SecureRandomByteGenerationModel.makeBytes(count: length.entropyByteCount))
            return try Mnemonic(
                parsed: MnemonicCodecModel.makeMnemonic(entropy: entropy, language: language)
            )
        }

        public func deriveSeed(passphrase: String = "") throws -> Data {
            try MnemonicCodecModel.deriveSeed(phrase: phrase, passphrase: passphrase)
        }

        internal init(parsed: MnemonicCodecModel.ParsedMnemonic) {
            self.words = parsed.words.map(Word.init)
            self.length = parsed.length
            self.language = parsed.language
        }
    }
}
