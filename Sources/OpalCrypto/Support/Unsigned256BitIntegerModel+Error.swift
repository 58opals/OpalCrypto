// Unsigned256BitIntegerModel+Error.swift

import Foundation

extension Unsigned256BitIntegerModel {
    internal enum Error: Swift.Error, Equatable {
        case invalidDataLength(expected: Int, actual: Int)
    }
}
