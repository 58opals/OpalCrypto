// MnemonicWordListCache.swift

import Foundation

internal final class MnemonicWordListCache: @unchecked Sendable {
    private let condition = NSCondition()
    private var cachedWordLists: [OpalCrypto.Key.Mnemonic.Word.Language: MnemonicWordListRepository.WordListData] = [:]
    private var loadingLanguages: Set<OpalCrypto.Key.Mnemonic.Word.Language> = []

    internal func load(
        language: OpalCrypto.Key.Mnemonic.Word.Language,
        loader: () throws -> MnemonicWordListRepository.WordListData
    ) throws -> MnemonicWordListRepository.WordListData {
        condition.lock()
        while true {
            if let cachedWordList = cachedWordLists[language] {
                condition.unlock()
                return cachedWordList
            }

            if !loadingLanguages.contains(language) {
                loadingLanguages.insert(language)
                condition.unlock()

                do {
                    let loadedWordList = try loader()
                    condition.lock()
                    cachedWordLists[language] = loadedWordList
                    loadingLanguages.remove(language)
                    condition.broadcast()
                    condition.unlock()
                    return loadedWordList
                } catch {
                    condition.lock()
                    loadingLanguages.remove(language)
                    condition.broadcast()
                    condition.unlock()
                    throw error
                }
            }

            condition.wait()
        }
    }
}
