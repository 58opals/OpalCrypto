// PasswordBasedKeyDerivationFunction2Model~BlockComputation.swift

import CryptoKit
import Foundation

extension PasswordBasedKeyDerivationFunction2Model {
    func computeBlock(blockNumber: Int) throws -> Array<UInt8> {
        var blockInput = Data()
        blockInput.reserveCapacity(salt.count + 4)
        blockInput.append(salt)
        blockInput.appendUInt32BigEndian(UInt32(blockNumber))

        let firstAuthenticationCode = HMAC<SHA512>.authenticationCode(for: blockInput, using: symmetricKey)

        var currentBlock = Array(firstAuthenticationCode)
        var blockResult = currentBlock

        if iterationCount > 1 {
            for _ in 2...iterationCount {
                try Task.checkCancellation()
                let authenticationCode = HMAC<SHA512>.authenticationCode(for: currentBlock, using: symmetricKey)
                // SAFETY: HMAC<SHA512>.MAC exposes exactly sha512BlockSize
                // initialized bytes for this closure. UInt8 has byte alignment,
                // indices stay within that fixed digest, and no view escapes.
                authenticationCode.withUnsafeBytes { buffer in
                    let bytes = buffer.bindMemory(to: UInt8.self)
                    for index in 0..<sha512BlockSize {
                        let value = bytes[index]
                        currentBlock[index] = value
                        blockResult[index] ^= value
                    }
                }
            }
        }

        return blockResult
    }
}
