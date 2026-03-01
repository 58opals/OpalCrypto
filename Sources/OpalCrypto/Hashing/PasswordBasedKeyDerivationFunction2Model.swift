// PasswordBasedKeyDerivationFunction2Model.swift

import Foundation
import CryptoKit

public struct PasswordBasedKeyDerivationFunction2Model {
    public enum Error: Swift.Error {
        case invalidParameters
        case keyLengthExceedsLimit
    }
    
    let symmetricKey: SymmetricKey
    let salt: Data
    let iterationCount: Int
    let blockCount: Int
    let derivedKeyLength: Int
    
    let sha512BlockSize = (512 / 8)
    
    public init(password: Data, salt: Data, iterationCount: Int = 4096, derivedKeyLength: Int? = nil) throws {
        precondition(iterationCount > 0)
        let symmetricKey = SymmetricKey(data: password)
        
        guard iterationCount > 0 && !salt.isEmpty else { throw Error.invalidParameters }
        
        
        self.derivedKeyLength = derivedKeyLength ?? sha512BlockSize
        let keyLengthFinal = Double(self.derivedKeyLength)
        let hLen = Double(sha512BlockSize)
        if keyLengthFinal > (pow(2, 32) - 1) * hLen { throw Error.keyLengthExceedsLimit }
        
        self.symmetricKey = symmetricKey
        self.salt = salt
        self.iterationCount = iterationCount
        self.blockCount = Int(ceil(keyLengthFinal / hLen))
    }
    
    public func deriveKey() throws -> Data {
        var derivedKey = Array<UInt8>(repeating: 0, count: self.blockCount * sha512BlockSize)
        var derivedKeyIndex = 0
        for blockIndex in 1...self.blockCount {
            let block = try computeBlock(self.salt, blockNumber: blockIndex)
            let endIndex = derivedKeyIndex + block.count
            derivedKey.replaceSubrange(derivedKeyIndex..<endIndex, with: block)
            derivedKeyIndex = endIndex
        }
        return Data(Array(derivedKey.prefix(self.derivedKeyLength)))
    }
}
