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
            derivedKeyLength: 64
        ).deriveKey()
    }

    internal static func entropy(
        from words: [String],
        language: OpalCrypto.Key.Mnemonic.Word.Language,
        length: OpalCrypto.Key.Mnemonic.Length
    ) throws -> Data {
        let wordList = try MnemonicWordListRepository.load(language)
        let entropyBitCount = length.entropyByteCount * 8
        for word in words {
            guard wordList.indexLookup[word] != nil else {
                throw OpalCrypto.Key.Mnemonic.Error.invalidWord(word)
            }
        }

        var entropy = Data(repeating: 0, count: length.entropyByteCount)
        var entropyWriteBitIndex = 0
        var actualChecksumValue: UInt8 = 0

        for word in words {
            let wordIndex = wordList.indexLookup[word]!
            for shift in stride(from: 10, through: 0, by: -1) {
                let bit = (wordIndex >> shift) & 1
                if entropyWriteBitIndex < entropyBitCount {
                    if bit == 1 {
                        entropy[entropyWriteBitIndex / 8] |= UInt8(
                            1 << (7 - (entropyWriteBitIndex % 8))
                        )
                    }
                    entropyWriteBitIndex += 1
                } else {
                    actualChecksumValue = (actualChecksumValue << 1) | UInt8(bit)
                }
            }
        }

        let expectedChecksumValue = checksumValue(
            from: entropy,
            count: length.checksumBitCount
        )
        guard expectedChecksumValue == actualChecksumValue else {
            throw OpalCrypto.Key.Mnemonic.Error.invalidChecksum
        }
        return entropy
    }

    private static func words(
        from entropy: Data,
        wordList: [String],
        length: OpalCrypto.Key.Mnemonic.Length
    ) throws -> [String] {
        guard entropy.count == length.entropyByteCount else {
            throw OpalCrypto.Key.Mnemonic.Error.invalidEntropyLength(actual: entropy.count)
        }

        let entropyBitCount = entropy.count * 8
        let checksum = checksumValue(from: entropy, count: length.checksumBitCount)
        var resolvedWords: [String] = .init()
        resolvedWords.reserveCapacity(length.rawValue)

        for wordIndexPosition in 0..<length.rawValue {
            var wordIndex = 0
            let startBitIndex = wordIndexPosition * 11
            for offset in 0..<11 {
                let bitIndex = startBitIndex + offset
                wordIndex <<= 1
                if bitIndex < entropyBitCount {
                    let entropyByte = entropy[bitIndex / 8]
                    if ((entropyByte >> (7 - (bitIndex % 8))) & 1) == 1 {
                        wordIndex |= 1
                    }
                } else {
                    let checksumBitIndex = bitIndex - entropyBitCount
                    if ((checksum >> (length.checksumBitCount - 1 - checksumBitIndex)) & 1) == 1 {
                        wordIndex |= 1
                    }
                }
            }
            resolvedWords.append(wordList[wordIndex])
        }

        return resolvedWords
    }

    private static func checksumValue(from entropy: Data, count: Int) -> UInt8 {
        let checksum = SecureHashAlgorithm256Model.hash(entropy)
        var value: UInt8 = 0
        for bitIndex in 0..<count {
            value <<= 1
            let byte = checksum[bitIndex / 8]
            if ((byte >> (7 - (bitIndex % 8))) & 1) == 1 {
                value |= 1
            }
        }
        return value
    }

    private static func length(forWordCount count: Int) throws -> OpalCrypto.Key.Mnemonic.Length {
        guard let length = OpalCrypto.Key.Mnemonic.Length(rawValue: count) else {
            throw OpalCrypto.Key.Mnemonic.Error.invalidWordCount(actual: count)
        }
        return length
    }

    private static func length(
        forEntropyByteCount count: Int
    ) throws -> OpalCrypto.Key.Mnemonic.Length {
        switch count {
        case 16:
            return .words12
        case 20:
            return .words15
        case 24:
            return .words18
        case 28:
            return .words21
        case 32:
            return .words24
        default:
            throw OpalCrypto.Key.Mnemonic.Error.invalidEntropyLength(actual: count)
        }
    }
}

internal extension OpalCrypto.Key.Mnemonic.Length {
    var entropyByteCount: Int {
        (rawValue / 3) * 4
    }

    var checksumBitCount: Int {
        entropyByteCount / 4
    }
}
