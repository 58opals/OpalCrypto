// OpalCrypto.SecureRandom+Error.swift

import Foundation

extension OpalCrypto.SecureRandom {
    public enum Error: Swift.Error, Equatable, Sendable {
        case invalidByteCount(minimum: Int, maximum: Int, actual: Int)
        case generationFailed(status: Int32)
    }
}
