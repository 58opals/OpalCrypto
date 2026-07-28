// MnemonicCodecModel.swift

import Foundation

internal enum MnemonicCodecModel {
    internal static func normalizeWord(_ string: String) -> String {
        string
            .decomposedStringWithCompatibilityMapping
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    internal static func normalizePhrase(_ string: String) -> String {
        string.decomposedStringWithCompatibilityMapping
    }

    internal static func makeMnemonic(
        entropy: Data,
        language: OpalCrypto.Key.Mnemonic.Word.Language
    ) throws -> ParsedMnemonic {
        let length = try length(forEntropyByteCount: entropy.count)
        let wordList = try MnemonicWordListRepository.load(language)
        let words = try words(from: entropy, wordList: wordList.words, length: length)
        return ParsedMnemonic(words: words, length: length, language: language)
    }

    internal static func deriveSeed(phrase: String, passphrase: String) throws -> Data {
        let normalizedPhrase = normalizePhrase(phrase)
        let normalizedPassphrase = normalizePhrase(passphrase)
        let salt = "mnemonic" + normalizedPassphrase
        return try PasswordBasedKeyDerivationFunction2Model(
            password: Data(normalizedPhrase.utf8),
            salt: Data(salt.utf8),
            iterationCount: 2048,
            derivedKeyLength: 64,
            maximumWorkUnitCount: 2048
        ).deriveKey()
    }
}
