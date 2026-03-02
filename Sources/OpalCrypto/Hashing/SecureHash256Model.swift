// SecureHash256Model.swift

import Foundation

internal struct SecureHash256Model {
    internal static func hash(_ data: Data) -> Data {
        let firstHash = SecureHashAlgorithm256Model.hash(data)
        let secondHash = SecureHashAlgorithm256Model.hash(firstHash)
        return secondHash
    }
    
    internal static func computeChecksum(for data: Data) -> Data {
        let hash256 = SecureHash256Model.hash(data)
        let checksum = hash256[0..<4]
        return checksum
    }
}
