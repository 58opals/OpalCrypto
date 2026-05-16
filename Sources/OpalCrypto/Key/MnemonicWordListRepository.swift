// MnemonicWordListRepository.swift

import Foundation

internal enum MnemonicWordListRepository {

    private static let cache = MnemonicWordListCache()

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
        return try makeWordListData(words: words, language: language)
    }

    internal static func makeWordListData(
        words: [String],
        language: OpalCrypto.Key.Mnemonic.Word.Language
    ) throws -> WordListData {
        guard words.count == 2048 else {
            throw OpalCrypto.Key.Mnemonic.Error.invalidWordList(
                language: language,
                actualCount: words.count
            )
        }
        guard words.allSatisfy({ !$0.isEmpty }) else {
            throw OpalCrypto.Key.Mnemonic.Error.invalidWordList(
                language: language,
                actualCount: words.count
            )
        }
        guard words.allSatisfy({ !$0.contains(where: \.isWhitespace) }) else {
            throw OpalCrypto.Key.Mnemonic.Error.invalidWordList(
                language: language,
                actualCount: words.count
            )
        }
        let indexLookup = Dictionary(words.enumerated().map { ($1, $0) }, uniquingKeysWith: { firstIndex, _ in firstIndex })
        guard indexLookup.count == 2048 else {
            throw OpalCrypto.Key.Mnemonic.Error.invalidWordList(
                language: language,
                actualCount: indexLookup.count
            )
        }
        guard words == words.sorted() else {
            throw OpalCrypto.Key.Mnemonic.Error.invalidWordList(
                language: language,
                actualCount: words.count
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
