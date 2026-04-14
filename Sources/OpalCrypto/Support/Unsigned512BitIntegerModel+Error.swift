// Unsigned512BitIntegerModel+Error.swift

import Foundation

extension Unsigned512BitIntegerModel {
    internal enum Error: Swift.Error, Equatable {
        case invalidDataLength(expected: Int, actual: Int)
    }
}
