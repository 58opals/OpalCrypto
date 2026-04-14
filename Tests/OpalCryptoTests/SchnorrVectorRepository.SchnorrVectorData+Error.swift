// SchnorrVectorRepository.SchnorrVectorData+Error.swift

import Foundation

extension SchnorrVectorRepository.SchnorrVectorData {
    enum Error: Swift.Error, Equatable, CustomStringConvertible {
        case emptyHexField(field: String, index: Int)
        case oddHexLength(field: String, index: Int, count: Int)
        case invalidHexPair(field: String, index: Int, byteOffset: Int, pair: String)
        case invalidByteCount(field: String, index: Int, expected: Int, actual: Int)

        var description: String {
            switch self {
            case .emptyHexField(let field, let index): return "Vector \(index): field '\(field)' must not be empty."
            case .oddHexLength(let field, let index, let count): return "Vector \(index): field '\(field)' has odd hex length \(count)."
            case .invalidHexPair(let field, let index, let byteOffset, let pair): return "Vector \(index): field '\(field)' has invalid hex '\(pair)' at byte offset \(byteOffset)."
            case .invalidByteCount(let field, let index, let expected, let actual): return "Vector \(index): field '\(field)' expected \(expected) bytes but decoded \(actual)."
            }
        }
    }
}
