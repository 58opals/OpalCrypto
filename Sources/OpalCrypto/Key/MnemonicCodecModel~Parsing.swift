// MnemonicCodecModel~Parsing.swift

import Foundation

extension MnemonicCodecModel {
    internal static func parse(
        phrase: String,
        language: OpalCrypto.Key.Mnemonic.Word.Language?
    ) throws -> ParsedMnemonic {
        let normalizedWords = normalizePhrase(phrase)
            .split(whereSeparator: \.isWhitespace)
            .map { normalizeWord(String($0)) }
        return try parse(words: normalizedWords, language: language)
    }

    internal static func parse(
        words: [String],
        language: OpalCrypto.Key.Mnemonic.Word.Language?
    ) throws -> ParsedMnemonic {
        let normalizedWords = words.map(normalizeWord)
        let length = try length(forWordCount: normalizedWords.count)

        if let language {
            _ = try entropy(from: normalizedWords, language: language, length: length)
            return ParsedMnemonic(words: normalizedWords, length: length, language: language)
        }

        var matches: [ParsedMnemonic] = []
        var foundChecksumMismatch = false
        var firstInvalidWord: String?

        for candidateLanguage in OpalCrypto.Key.Mnemonic.Word.Language.allCases {
            do {
                _ = try entropy(from: normalizedWords, language: candidateLanguage, length: length)
                matches.append(
                    ParsedMnemonic(
                        words: normalizedWords,
                        length: length,
                        language: candidateLanguage
                    )
                )
            } catch let error as OpalCrypto.Key.Mnemonic.Error {
                switch error {
                case .invalidChecksum:
                    foundChecksumMismatch = true
                case .invalidWord(let word):
                    firstInvalidWord = firstInvalidWord ?? word
                default:
                    break
                }
            }
        }

        if matches.count == 1, let match = matches.first {
            return match
        }
        if matches.count > 1 {
            throw OpalCrypto.Key.Mnemonic.Error.ambiguousLanguage
        }
        if foundChecksumMismatch {
            throw OpalCrypto.Key.Mnemonic.Error.invalidChecksum
        }
        throw OpalCrypto.Key.Mnemonic.Error.invalidWord(firstInvalidWord ?? "")
    }

    static func length(forWordCount count: Int) throws -> OpalCrypto.Key.Mnemonic.Length {
        guard let length = OpalCrypto.Key.Mnemonic.Length(rawValue: count) else {
            throw OpalCrypto.Key.Mnemonic.Error.invalidWordCount(actual: count)
        }
        return length
    }
}
