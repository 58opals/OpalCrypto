// FieldElementModel+Error.swift

import Foundation

extension FieldElementModel {
    enum Error: Swift.Error, Equatable {
        case invalidFieldValue
        case invalidDataLength(expected: Int, actual: Int)
    }
}
