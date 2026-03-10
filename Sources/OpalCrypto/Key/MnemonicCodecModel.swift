// MnemonicCodecModel.swift

import Foundation

internal enum MnemonicCodecModel {
    internal struct ParsedMnemonic: Sendable, Equatable {
        internal let words: [String]
        internal let length: OpalCrypto.Key.Mnemonic.Length
        internal let language: OpalCrypto.Key.Mnemonic.Word.Language
    }

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
            .components(separatedBy: .whitespacesAndNewlines)
            .map(normalizeWord)
            .filter { !$0.isEmpty }
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
        var bits: [Bool] = []
        bits.reserveCapacity(words.count * 11)

        for word in words {
            guard let wordIndex = wordList.indexLookup[word] else {
                throw OpalCrypto.Key.Mnemonic.Error.invalidWord(word)
            }
            for shift in stride(from: 10, through: 0, by: -1) {
                bits.append(((wordIndex >> shift) & 1) == 1)
            }
        }

        let entropyBitCount = length.entropyByteCount * 8
        var entropy = Data(repeating: 0, count: length.entropyByteCount)
        for bitIndex in 0..<entropyBitCount where bits[bitIndex] {
            entropy[bitIndex / 8] |= UInt8(1 << (7 - (bitIndex % 8)))
        }

        let checksumBits = checksumBits(from: entropy, count: length.checksumBitCount)
        let actualChecksum = Array(bits[entropyBitCount..<(entropyBitCount + length.checksumBitCount)])
        guard checksumBits == actualChecksum else {
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

        var bits: [Bool] = []
        bits.reserveCapacity(entropy.count * 8 + length.checksumBitCount)
        for byte in entropy {
            for shift in stride(from: 7, through: 0, by: -1) {
                bits.append(((byte >> shift) & 1) == 1)
            }
        }
        bits.append(contentsOf: checksumBits(from: entropy, count: length.checksumBitCount))

        return stride(from: 0, to: bits.count, by: 11).map { startIndex in
            var wordIndex = 0
            for offset in 0..<11 {
                wordIndex <<= 1
                if bits[startIndex + offset] {
                    wordIndex |= 1
                }
            }
            return wordList[wordIndex]
        }
    }

    private static func checksumBits(from entropy: Data, count: Int) -> [Bool] {
        let checksum = SecureHashAlgorithm256Model.hash(entropy)
        return (0..<count).map { bitIndex in
            let byte = checksum[bitIndex / 8]
            return ((byte >> (7 - (bitIndex % 8))) & 1) == 1
        }
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
