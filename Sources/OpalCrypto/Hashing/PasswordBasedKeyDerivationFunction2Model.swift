// PasswordBasedKeyDerivationFunction2Model.swift

import Foundation
import CryptoKit

internal struct PasswordBasedKeyDerivationFunction2Model {
    internal enum Error: Swift.Error {
        case invalidParameters
        case keyLengthExceedsLimit
    }
    
    let symmetricKey: SymmetricKey
    let salt: Data
    let iterationCount: Int
    let blockCount: Int
    let derivedKeyLength: Int
    
    let sha512BlockSize = (512 / 8)
    
    internal init(password: Data, salt: Data, iterationCount: Int = 4096, derivedKeyLength: Int? = nil) throws {
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
    
    internal func deriveKey() throws -> Data {
        var derivedKey = Data()
        derivedKey.reserveCapacity(self.derivedKeyLength)
        var remainingByteCount = derivedKeyLength
        for blockIndex in 1...self.blockCount {
            let block = try computeBlock(blockNumber: blockIndex)
            if remainingByteCount >= block.count {
                derivedKey.append(contentsOf: block)
                remainingByteCount -= block.count
            } else {
                derivedKey.append(contentsOf: block.prefix(remainingByteCount))
                remainingByteCount = 0
                break
            }
        }
        return derivedKey
    }
}
