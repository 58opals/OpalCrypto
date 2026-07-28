// Base58EncodingCodec.swift

import Foundation

internal struct Base58EncodingCodec {
    static let characters: [Character] = [
        "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "A", "B", "C", "D", "E", "F", "G", "H",
        "J", "K", "L", "M", "N",
        "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k",
        "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"
    ]
    private static let baseNumber: Int = characters.count
    private static let asciiLookup: [Int16] = {
        var lookup = Array(repeating: Int16(-1), count: 128)
        for (index, character) in characters.enumerated() {
            lookup[Int(character.asciiValue!)] = Int16(index)
        }
        return lookup
    }()
    
    internal static func encode(_ data: Data) -> String {
        var value = LargeUnsignedIntegerArithmeticModel(data)
        var charactersResult: [Character] = .init()
        charactersResult.reserveCapacity(Swift.max(1, data.count * 2))
        while !value.isZero {
            let remainder = value.divide(by: UInt64(baseNumber))
            charactersResult.append(characters[Int(remainder)])
        }
        
        let leadingZeroBytes = data.prefix { $0 == 0 }.count
        if leadingZeroBytes > 0 {
            charactersResult.append(contentsOf: repeatElement(characters.first!, count: leadingZeroBytes))
        }
        
        return String(charactersResult.reversed())
    }
    
    internal static func decode(
        _ base58: String,
        maximumDecodedByteCount: Int
    ) throws -> Data {
        guard maximumDecodedByteCount >= 0 else {
            throw Error.invalidMaximumDecodedByteCount(actual: maximumDecodedByteCount)
        }

        var total = LargeUnsignedIntegerArithmeticModel.zero
        var leadingOneCount = 0
        var isReadingLeadingOnes = true
        
        for asciiValue in base58.utf8 {
            guard asciiValue < 128 else { throw Error.invalidCharacterFound }
            let value = asciiLookup[Int(asciiValue)]
            guard value >= 0 else { throw Error.invalidCharacterFound }
            if isReadingLeadingOnes, value == 0 {
                leadingOneCount += 1
                guard leadingOneCount <= maximumDecodedByteCount else {
                    throw Error.decodedDataExceedsMaximumByteCount(
                        maximum: maximumDecodedByteCount
                    )
                }
            } else {
                isReadingLeadingOnes = false
            }
            total.multiply(by: UInt64(baseNumber))
            total.add(UInt64(value))
            guard total.serializedByteCount <= maximumDecodedByteCount - leadingOneCount else {
                throw Error.decodedDataExceedsMaximumByteCount(
                    maximum: maximumDecodedByteCount
                )
            }
        }
        
        var decoded = Data(repeating: 0, count: leadingOneCount)
        decoded.append(total.serialize())
        return decoded
    }
}
