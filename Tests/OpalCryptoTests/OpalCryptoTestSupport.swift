// OpalCryptoTestSupport.swift

import CommonCrypto
import Foundation
import Testing
@testable import OpalCrypto

enum OpalCryptoTestSupport {
    private static let performanceSmokeEnvironmentKey = "OPALCRYPTO_RUN_PERF_TESTS"

    // Keep heavy smoke coverage opt-in so plain `swift test` stays fast.
    static var isPerformanceSmokeEnabled: Bool {
        ProcessInfo.processInfo.environment[performanceSmokeEnvironmentKey] == "1"
    }

    static func makePrivateKeys(count: Int) -> [Data] {
        (1...count).map(makePrivateKey)
    }

    static func makePrivateKey(_ value: Int) -> Data {
        var privateKey = Data(repeating: 0x00, count: 32)
        let resolvedValue = UInt32(value)
        privateKey[28] = UInt8((resolvedValue >> 24) & 0xff)
        privateKey[29] = UInt8((resolvedValue >> 16) & 0xff)
        privateKey[30] = UInt8((resolvedValue >> 8) & 0xff)
        privateKey[31] = UInt8(resolvedValue & 0xff)
        return privateKey
    }

    static func makePaddedPlaintext(
        message: Data,
        paddedPlaintextLength: Int
    ) -> Data {
        var plaintext = Data()
        plaintext.reserveCapacity(paddedPlaintextLength)
        plaintext.appendUInt32BigEndian(UInt32(message.count))
        plaintext.append(message)
        plaintext.append(
            Data(repeating: 0x00, count: paddedPlaintextLength - plaintext.count)
        )
        return plaintext
    }

    static func aes256CbcCrypt(
        _ input: Data,
        key: Data,
        operation: CCOperation
    ) throws -> Data {
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

        #expect(status == kCCSuccess)
        output.removeSubrange(outputLength..<output.count)
        return output
    }
}
