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
            for character in string {
                let normalizedCharacter = try normalizeCharacter(character)

                if let index = characters.firstIndex(of: normalizedCharacter) {
                    data.append(UInt8(index))
                } else {
                    throw Error.invalidCharacterFound
                }
            }
        case false:
            let normalizedCharacters = try string.map(normalizeCharacter)
            let leadingZeroCharacterCount = normalizedCharacters.prefix(while: { $0 == zeroCharacter }).count
            var value = LargeUnsignedIntegerArithmeticModel(0)
            for normalizedCharacter in normalizedCharacters {
                if let index = characters.firstIndex(of: normalizedCharacter) {
                    value.multiply(by: baseNumber)
                    value.add(index)
                } else {
                    throw Error.invalidCharacterFound
                }
            }
            data = Data(repeating: 0x00, count: leadingZeroCharacterCount)
            data.append(value.serialize())
        }
        return data
    }

    private static func normalizeCharacter(_ character: Character) throws -> Character {
        guard let asciiValue = character.asciiValue else { return character }

        switch asciiValue {
        case 0x41...0x5A:
            let normalizedAsciiValue = asciiValue &+ 0x20
            let scalar = UnicodeScalar(normalizedAsciiValue)
            return Character(scalar)
        default:
            return character
        }
    }
}
