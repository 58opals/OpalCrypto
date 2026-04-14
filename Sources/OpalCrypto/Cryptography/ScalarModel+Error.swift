// ScalarModel+Error.swift

import Foundation

extension ScalarModel {
    enum Error: Swift.Error, Equatable {
        case invalidDataLength(expected: Int, actual: Int)
        case invalidScalarValue
        case zeroNotAllowed
    }
}
