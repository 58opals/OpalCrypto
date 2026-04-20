// CommunicationBoxModel~Cipher.swift

import CommonCrypto
import Foundation

extension CommunicationBoxModel {
    static func crypt(
        _ input: Data,
        key: Data,
        operation: CCOperation
    ) throws -> Data {
        guard key.count == kCCKeySizeAES256 else {
            throw Error.invalidSymmetricKeyLength(actual: key.count)
        }
        guard input.count.isMultiple(of: kCCBlockSizeAES128) else {
            throw Error.invalidCiphertext
        }

        let initializationVector = Data(repeating: 0x00, count: kCCBlockSizeAES128)
        var output = Data(repeating: 0x00, count: input.count + kCCBlockSizeAES128)
        let outputCapacity = output.count
        var outputLength = 0

        let status = output.withUnsafeMutableBytes { outputBuffer in
            input.withUnsafeBytes { inputBuffer in
                key.withUnsafeBytes { keyBuffer in
                    initializationVector.withUnsafeBytes { ivBuffer in
                        CCCrypt(
                            operation,
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyBuffer.baseAddress,
                            key.count,
                            ivBuffer.baseAddress,
                            inputBuffer.baseAddress,
                            input.count,
                            outputBuffer.baseAddress,
                            outputCapacity,
                            &outputLength
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw Error.cryptographyFailure
        }
        output.removeSubrange(outputLength..<output.count)
        return output
    }
}
