// SecureHash160Model.swift

import Foundation

struct SecureHash160Model {
    static func hash(_ data: Data) -> Data {
        let sha256 = SecureHashAlgorithm256Model.hash(data)
        let ripemd160 = RipeMessageDigest160Model.hash(sha256)
        return ripemd160
    }
}
