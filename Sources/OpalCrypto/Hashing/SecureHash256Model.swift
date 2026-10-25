// SecureHash256Model.swift

import Foundation

internal struct SecureHash256Model {
    internal static func hash(_ data: Data) -> Data {
        let firstHash = SecureHashAlgorithm256Model.hash(data)
        let secondHash = SecureHashAlgorithm256Model.hash(firstHash)
        return secondHash
    }
    
}
