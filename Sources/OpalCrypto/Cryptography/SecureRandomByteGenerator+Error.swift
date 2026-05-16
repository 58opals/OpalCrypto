// SecureRandomByteGenerator+Error.swift

import Foundation
import Security

extension SecureRandomByteGenerator {
    internal enum Error: Swift.Error, Equatable, Sendable {
        case failed(status: Int32)
    }
}
