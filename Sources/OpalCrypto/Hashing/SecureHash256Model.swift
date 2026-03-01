// SecureHash256Model.swift

import Foundation

public struct SecureHash256Model {
    public static func hash(_ data: Data) -> Data {
        let firstHash = SecureHashAlgorithm256Model.hash(data)
        let secondHash = SecureHashAlgorithm256Model.hash(firstHash)
        return secondHash
    }
    
    public static func computeChecksum(for data: Data) -> Data {
        let hash256 = SecureHash256Model.hash(data)
        let checksum = hash256[0..<4]
        return checksum
    }
}
