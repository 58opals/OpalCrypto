// OpalCrypto.Key.Mnemonic+WordList.swift

import Foundation

extension OpalCrypto.Key.Mnemonic {
    /// A BIP-39 language word list with random-access indexing and efficient lookup.
    public struct WordList: Sendable, Equatable, RandomAccessCollection {
        public typealias Element = Word
        public typealias Index = Int

        public let language: Word.Language
        public let words: [Word]

        internal let indexLookup: [String: Int]

        public var startIndex: Int {
            words.startIndex
        }

        public var endIndex: Int {
            words.endIndex
        }

        public var count: Int {
            words.count
        }

        /// Returns the word at `index`.
        public subscript(index: Int) -> Word {
            words[index]
        }

        /// Loads the canonical BIP-39 word list for `language`.
        public static func load(_ language: Word.Language) throws -> WordList {
            let wordList = try MnemonicWordListRepository.load(language)
            return WordList(language: language, wordList: wordList)
        }

        /// Returns whether this list contains `word`.
        public func contains(_ word: Word) -> Bool {
            indexLookup[word.text] != nil
        }

        /// Returns the index of `word`, or `nil` when it is absent.
        public func firstIndex(of word: Word) -> Int? {
            indexLookup[word.text]
        }

        /// Returns the index of `word`, or `nil` when it is absent.
        ///
        /// Prefer the collection-standard ``firstIndex(of:)`` operation in new code.
        public func index(of word: Word) -> Int? {
            firstIndex(of: word)
        }

        /// Returns the position immediately after `index`.
        public func index(after index: Int) -> Int {
            words.index(after: index)
        }

        /// Returns the position immediately before `index`.
        public func index(before index: Int) -> Int {
            words.index(before: index)
        }

        /// Offsets `index` by `distance` positions.
        public func index(_ index: Int, offsetBy distance: Int) -> Int {
            words.index(index, offsetBy: distance)
        }

        /// Returns the number of positions between two indices.
        public func distance(from start: Int, to end: Int) -> Int {
            words.distance(from: start, to: end)
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
