// SecureHash160Model.swift

import Foundation

internal struct SecureHash160Model {
    internal static func hash(_ data: Data) -> Data {
        let sha256 = SecureHashAlgorithm256Model.hash(data)
        let ripemd160 = RIPEMD160Model.hash(sha256)
        return ripemd160
    }
}
