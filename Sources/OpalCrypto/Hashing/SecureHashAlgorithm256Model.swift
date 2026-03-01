// SecureHashAlgorithm256Model.swift

import Foundation
import CryptoKit

struct SecureHashAlgorithm256Model {
    static func hash(_ data: Data) -> Data {
        let digest = CryptoKit.SHA256.hash(data: data)
        return .init(digest)
    }
}
