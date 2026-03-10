// MnemonicWordListRepository.swift

import Foundation

internal enum MnemonicWordListRepository {
    internal struct WordListData: Sendable, Equatable {
        internal let words: [String]
        internal let indexLookup: [String: Int]
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var cachedWordLists: [OpalCrypto.Key.Mnemonic.Word.Language: WordListData] = [:]

    internal static func load(
        _ language: OpalCrypto.Key.Mnemonic.Word.Language
    ) throws -> WordListData {
        lock.lock()
        if let cachedWordList = cachedWordLists[language] {
            lock.unlock()
            return cachedWordList
        }
        lock.unlock()

        guard let resourceURL = Bundle.module.url(
            forResource: language.resourceName,
            withExtension: "txt"
        ) else {
            throw OpalCrypto.Key.Mnemonic.Error.wordListResourceMissing(language: language)
        }

        let resourceContents = try String(contentsOf: resourceURL, encoding: .utf8)
        let words = resourceContents
            .components(separatedBy: .newlines)
            .map(MnemonicCodecModel.normalizeWord)
            .filter { !$0.isEmpty }
        guard words.count == 2048 else {
            throw OpalCrypto.Key.Mnemonic.Error.invalidWordList(
                language: language,
                actualCount: words.count
            )
        }

        let indexLookup = Dictionary(uniqueKeysWithValues: words.enumerated().map { ($1, $0) })
        guard indexLookup.count == 2048 else {
            throw OpalCrypto.Key.Mnemonic.Error.invalidWordList(
                language: language,
                actualCount: indexLookup.count
            )
        }

        let wordList = WordListData(words: words, indexLookup: indexLookup)

        lock.lock()
        cachedWordLists[language] = wordList
        lock.unlock()

        return wordList
    }
}

internal extension OpalCrypto.Key.Mnemonic.Word.Language {
    var resourceName: String {
        rawValue
    }
}
