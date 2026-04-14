// OpalCrypto.Key.Mnemonic+WordList.swift

import Foundation

extension OpalCrypto.Key.Mnemonic {
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
}
