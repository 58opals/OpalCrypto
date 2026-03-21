// PasswordBasedKeyDerivationFunction2Model+.swift

import Foundation
import CryptoKit

extension PasswordBasedKeyDerivationFunction2Model {
    func computeBlock(blockNumber: Int) throws -> Array<UInt8> {
        var blockInput = Data()
        blockInput.reserveCapacity(salt.count + 4)
        blockInput.append(salt)
        blockInput.appendUInt32BigEndian(UInt32(blockNumber))

        let firstAuthenticationCode = HMAC<SHA512>.authenticationCode(for: blockInput, using: symmetricKey)

        var currentBlock = Array<UInt8>(repeating: 0, count: sha512BlockSize)
        var blockResult = Array<UInt8>(repeating: 0, count: sha512BlockSize)

        firstAuthenticationCode.withUnsafeBytes { buffer in
            let bytes = buffer.bindMemory(to: UInt8.self)
            guard bytes.count == sha512BlockSize, let bytesAddress = bytes.baseAddress else {
                return
            }
            currentBlock.withUnsafeMutableBufferPointer { currentBuffer in
                currentBuffer.baseAddress?.update(from: bytesAddress, count: sha512BlockSize)
            }
            blockResult.withUnsafeMutableBufferPointer { resultBuffer in
                resultBuffer.baseAddress?.update(from: bytesAddress, count: sha512BlockSize)
            }
        }

        if iterationCount > 1 {
            for _ in 2...iterationCount {
                let authenticationCode = HMAC<SHA512>.authenticationCode(for: currentBlock, using: symmetricKey)
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
