// Data~Hexadecimal.swift

import Foundation

extension Data {
    init(hexadecimal: String) throws {
        let normalized = hexadecimal.trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalized.count.isMultiple(of: 2) else {
            throw HexadecimalDataError.invalidLength
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(normalized.count / 2)
        var cursor = normalized.startIndex
        while cursor < normalized.endIndex {
            let nextCursor = normalized.index(cursor, offsetBy: 2)
            let pair = normalized[cursor..<nextCursor]
            guard let byte = UInt8(pair, radix: 16) else {
                throw HexadecimalDataError.invalidCharacter
            }
            bytes.append(byte)
            cursor = nextCursor
        }
        self = Data(bytes)
    }
}
