// OpalCrypto.Key.Mnemonic+Error.swift

import Foundation

extension OpalCrypto.Key.Mnemonic {
    public enum Error: Swift.Error, Equatable {
        case invalidWordCount(actual: Int)
        case invalidEntropyLength(actual: Int)
        case invalidWord(String)
        case invalidChecksum
        case ambiguousLanguage
        case wordListResourceMissing(language: Word.Language)
        case invalidWordList(language: Word.Language, actualCount: Int)
    }
}
