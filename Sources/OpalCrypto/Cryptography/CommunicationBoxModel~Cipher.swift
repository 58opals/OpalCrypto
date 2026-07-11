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

        // SAFETY: The nested closures keep every Data allocation alive for the
        // complete CCCrypt call. The key is exactly 32 bytes, the IV is exactly
        // one AES block, and output owns outputCapacity writable bytes. A nil
        // input base address is possible only for a zero-length input, whose
        // matching byte count makes it valid for CommonCrypto to ignore.
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
