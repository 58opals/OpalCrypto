// MnemonicCodecModel~Entropy.swift

import Foundation

extension MnemonicCodecModel {
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

    static func words(
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
                    let entropyByte = entropy[
                        entropy.index(entropy.startIndex, offsetBy: bitIndex / 8)
                    ]
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

    static func checksumValue(from entropy: Data, count: Int) -> UInt8 {
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

    static func length(
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
