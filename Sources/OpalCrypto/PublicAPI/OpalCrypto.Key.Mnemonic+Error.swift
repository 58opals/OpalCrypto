// OpalCrypto.Key.Mnemonic+Error.swift

import Foundation

extension OpalCrypto.Key.Mnemonic {
    public enum Error: Swift.Error, Equatable {
        case invalidWordCount(actual: Int)
        case wordCountExceedsMaximum(maximum: Int)
        case phraseByteCountExceedsMaximum(maximum: Int, actual: Int)
        case wordByteCountExceedsMaximum(maximum: Int, actual: Int)
        case invalidEntropyLength(actual: Int)
        case invalidWord(String)
        case invalidChecksum
        case ambiguousLanguage
        case randomGenerationFailed(status: Int32)
        case wordListResourceMissing(language: Word.Language)
        case invalidWordList(language: Word.Language, actualCount: Int)
    }
}
