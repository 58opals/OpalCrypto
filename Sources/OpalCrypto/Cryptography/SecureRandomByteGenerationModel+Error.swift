// SecureRandomByteGenerationModel+Error.swift

import Foundation
import Security

extension SecureRandomByteGenerationModel {
    internal enum Error: Swift.Error, Equatable, Sendable {
        case failed(status: Int32)
    }
}
