// Base58EncodingModel.swift

import Foundation

internal struct Base58EncodingModel {
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
    
    internal static func decode(_ base58: String) -> Data? {
        var total = LargeUnsignedIntegerArithmeticModel.zero
        
        for asciiValue in base58.utf8 {
            guard asciiValue < 128 else { return nil }
            let value = asciiLookup[Int(asciiValue)]
            guard value >= 0 else { return nil }
            total.multiply(by: UInt64(baseNumber))
            total.add(UInt64(value))
        }
        
        var bytes: [UInt8] = .init()
        var current = total
        while !current.isZero {
            let remainder = current.divide(by: 256)
            bytes.append(UInt8(remainder))
        }
        bytes.reverse()
        
        let leadingOnes = base58.prefix { $0 == characters.first! }.count
        if leadingOnes > 0 {
            var prefixed: [UInt8] = .init(repeating: 0, count: leadingOnes)
            prefixed.append(contentsOf: bytes)
            return Data(prefixed)
        }
        
        return Data(bytes)
    }
}
