// Base32EncodingModel.swift

import Foundation

internal struct Base32EncodingModel {
    static let characters: [Character] = [
        "q", "p", "z", "r", "y", "9", "x", "8",
        "g", "f", "2", "t", "v", "d", "w", "0",
        "s", "3", "j", "n", "5", "4", "k", "h",
        "c", "e", "6", "m", "u", "a", "7", "l"
    ]
    private static let baseNumber: Int = characters.count
    private static let zeroCharacter = characters[0]
    private static let asciiLookup: [Int16] = {
        var lookup = Array(repeating: Int16(-1), count: 128)
        for (index, character) in characters.enumerated() {
            let asciiValue = character.asciiValue!
            lookup[Int(asciiValue)] = Int16(index)
            if (0x61...0x7A).contains(asciiValue) {
                lookup[Int(asciiValue - 0x20)] = Int16(index)
            }
        }
        return lookup
    }()

    internal static func encode(_ data: Data, interpretedAsFiveBitValues: Bool) throws -> String {
        switch interpretedAsFiveBitValues {
        case true:
            var result = String()
            result.reserveCapacity(data.count)
            for value in data {
                guard value < UInt8(characters.count) else {
                    throw Error.invalidFiveBitValue(actual: value)
                }
                result.append(characters[Int(value)])
            }
            return result
        case false:
            let leadingZeroByteCount = data.prefix(while: { $0 == 0 }).count
            var value = LargeUnsignedIntegerArithmeticModel(data)
            var charactersResult: [Character] = .init()
            charactersResult.reserveCapacity(Swift.max(1, data.count * 2))
            while !value.isZero {
                let remainder = value.divide(by: baseNumber)
                charactersResult.append(characters[remainder])
            }
            let leadingZeroPrefix = String(repeating: String(zeroCharacter), count: leadingZeroByteCount)
            return leadingZeroPrefix + String(charactersResult.reversed())
        }
    }

    internal static func decode(_ string: String, interpretedAsFiveBitValues: Bool) throws -> Data {
        var data = Data()
        switch interpretedAsFiveBitValues {
        case true:
            data.reserveCapacity(string.count)
            for asciiValue in string.utf8 {
                guard asciiValue < 128 else {
                    throw Error.invalidCharacterFound
                }
                let index = asciiLookup[Int(asciiValue)]
                guard index >= 0 else {
                    throw Error.invalidCharacterFound
                }
                data.append(UInt8(index))
            }
        case false:
            var value = LargeUnsignedIntegerArithmeticModel(0)
            var leadingZeroCharacterCount = 0
            var isReadingLeadingZeroes = true
            for asciiValue in string.utf8 {
                guard asciiValue < 128 else {
                    throw Error.invalidCharacterFound
                }
                let index = asciiLookup[Int(asciiValue)]
                guard index >= 0 else {
                    throw Error.invalidCharacterFound
                }
                if isReadingLeadingZeroes, index == 0 {
                    leadingZeroCharacterCount += 1
                } else {
                    isReadingLeadingZeroes = false
                }
                value.multiply(by: baseNumber)
                value.add(Int(index))
            }
            data = Data(repeating: 0x00, count: leadingZeroCharacterCount)
            data.append(value.serialize())
        }
        return data
    }
}
