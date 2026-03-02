// SecureHashAlgorithm256Model.swift

import Foundation
import CryptoKit

internal struct SecureHashAlgorithm256Model {
    internal static func hash(_ data: Data) -> Data {
        let digest = CryptoKit.SHA256.hash(data: data)
        return .init(digest)
    }
}
