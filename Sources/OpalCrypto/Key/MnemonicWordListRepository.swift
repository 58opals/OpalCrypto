// MnemonicWordListRepository.swift

import Foundation

internal enum MnemonicWordListRepository {

    private static let cache = MnemonicWordListCacheModel()

    internal static func load(
        _ language: OpalCrypto.Key.Mnemonic.Word.Language
    ) throws -> WordListData {
        try cache.load(language: language) {
            try makeWordListData(language: language)
        }
    }

    private static func makeWordListData(
        language: OpalCrypto.Key.Mnemonic.Word.Language
    ) throws -> WordListData {
        guard let resourceURL = Bundle.module.url(
            forResource: language.resourceName,
            withExtension: "txt"
        ) else {
            throw OpalCrypto.Key.Mnemonic.Error.wordListResourceMissing(language: language)
        }

        let resourceContents = try String(contentsOf: resourceURL, encoding: .utf8)
        let words = resourceContents
            .split(whereSeparator: \.isNewline)
            .map { MnemonicCodecModel.normalizeWord(String($0)) }
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

        return WordListData(words: words, indexLookup: indexLookup)
    }
}

internal extension OpalCrypto.Key.Mnemonic.Word.Language {
    var resourceName: String {
        rawValue
    }
}
