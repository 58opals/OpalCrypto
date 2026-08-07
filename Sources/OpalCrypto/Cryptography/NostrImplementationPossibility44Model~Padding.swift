// NostrImplementationPossibility44Model~Padding.swift

import Foundation

extension NostrImplementationPossibility44Model {
    static func pad(_ plaintext: Data) throws -> Data {
        let plaintextByteCount = plaintext.count
        guard plaintextByteCount > 0 else {
            throw Error.emptyPlaintext
        }
        guard plaintextByteCount <= standardMaximumPlaintextByteCount else {
            throw Error.plaintextByteCountExceedsStandardLimit(
                actual: plaintextByteCount
            )
        }
        let paddingByteCount = paddedPlaintextByteCount(plaintextByteCount)
            - plaintextByteCount
        var padded = Data()
        padded.reserveCapacity(prefixByteCount(plaintextByteCount) + plaintextByteCount + paddingByteCount)
        if plaintextByteCount < 65_536 {
            padded.append(UInt8(truncatingIfNeeded: plaintextByteCount >> 8))
            padded.append(UInt8(truncatingIfNeeded: plaintextByteCount))
        } else {
            padded.append(contentsOf: [0, 0])
            padded.append(UInt8(truncatingIfNeeded: plaintextByteCount >> 24))
            padded.append(UInt8(truncatingIfNeeded: plaintextByteCount >> 16))
            padded.append(UInt8(truncatingIfNeeded: plaintextByteCount >> 8))
            padded.append(UInt8(truncatingIfNeeded: plaintextByteCount))
        }
        padded.append(plaintext)
        padded.append(Data(repeating: 0, count: paddingByteCount))
        return padded
    }

    static func unpad(
        _ padded: Data,
        maximumPlaintextByteCount: Int
    ) throws -> Data {
        guard padded.count >= 2 else {
            throw Error.invalidPadding
        }
        let firstLength = (Int(padded[padded.startIndex]) << 8)
            | Int(padded[padded.startIndex + 1])
        let prefixLength: Int
        let plaintextLength: Int
        if firstLength == 0 {
            guard padded.count >= 6 else {
                throw Error.invalidPadding
            }
            prefixLength = 6
            plaintextLength = padded[padded.startIndex + 2 ..< padded.startIndex + 6]
                .reduce(0) { ($0 << 8) | Int($1) }
            guard plaintextLength >= 65_536 else {
                throw Error.invalidPadding
            }
        } else {
            prefixLength = 2
            plaintextLength = firstLength
        }
        try validatePlaintextByteCount(
            plaintextLength,
            maximumPlaintextByteCount: maximumPlaintextByteCount
        )
        let expectedByteCount = prefixLength
            + paddedPlaintextByteCount(plaintextLength)
        guard padded.count == expectedByteCount,
              prefixLength + plaintextLength <= padded.count else {
            throw Error.invalidPadding
        }
        let plaintextEnd = prefixLength + plaintextLength
        guard padded[plaintextEnd ..< padded.count].allSatisfy({ $0 == 0 }) else {
            throw Error.invalidPadding
        }
        return Data(padded[prefixLength ..< plaintextEnd])
    }

    static func paddedPlaintextByteCount(_ plaintextByteCount: Int) -> Int {
        if plaintextByteCount <= 32 {
            return 32
        }
        let nextPowerOfTwo = 1 << (Int.bitWidth - (plaintextByteCount - 1).leadingZeroBitCount)
        let chunkByteCount = nextPowerOfTwo <= 256
            ? 32
            : nextPowerOfTwo / 8
        return chunkByteCount * (((plaintextByteCount - 1) / chunkByteCount) + 1)
    }

    private static func prefixByteCount(_ plaintextByteCount: Int) -> Int {
        plaintextByteCount < 65_536 ? 2 : 6
    }
}
