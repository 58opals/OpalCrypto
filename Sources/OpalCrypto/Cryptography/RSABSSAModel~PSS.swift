// RSABSSAModel~PSS.swift

import CryptoKit
import Foundation

extension RSABSSAModel {
    internal static func encodePSS(
        message: Data,
        salt: Data,
        modulusBitCount: Int
    ) throws -> Data {
        let variant = OpalCrypto.RSABSSA.Variant.sha384PSSRandomized
        guard salt.count == variant.saltByteCount else {
            throw OpalCrypto.RSABSSA.Error.invalidMessageRepresentative
        }
        guard modulusBitCount > 1 else {
            throw OpalCrypto.RSABSSA.Error.invalidMessageRepresentative
        }

        let encodedBitCount = modulusBitCount - 1
        let encodedByteCount = (encodedBitCount + 7) / 8
        let digestByteCount = variant.messageDigestByteCount
        guard encodedByteCount >= digestByteCount + salt.count + 2 else {
            throw OpalCrypto.RSABSSA.Error.invalidMessageRepresentative
        }

        let messageDigest = hashSHA384(message)
        var digestInput = Data(repeating: 0, count: 8)
        digestInput.append(messageDigest)
        digestInput.append(salt)
        let digest = hashSHA384(digestInput)

        let dataBlockByteCount = encodedByteCount - digestByteCount - 1
        var dataBlock = Data(
            repeating: 0,
            count: dataBlockByteCount - salt.count - 1
        )
        dataBlock.append(0x01)
        dataBlock.append(salt)

        let mask = maskGenerationFunction1(
            seed: digest,
            outputByteCount: dataBlockByteCount
        )
        var maskedDataBlock = Data(
            zip(dataBlock, mask).map { $0 ^ $1 }
        )
        let unusedBitCount = encodedByteCount * 8 - encodedBitCount
        maskedDataBlock[maskedDataBlock.startIndex] &= UInt8(0xff >> unusedBitCount)

        var encodedMessage = maskedDataBlock
        encodedMessage.append(digest)
        encodedMessage.append(0xbc)
        return encodedMessage
    }

    private static func maskGenerationFunction1(
        seed: Data,
        outputByteCount: Int
    ) -> Data {
        var output = Data()
        output.reserveCapacity(outputByteCount)
        var counter: UInt32 = 0

        while output.count < outputByteCount {
            var input = seed
            input.append(UInt8(truncatingIfNeeded: counter >> 24))
            input.append(UInt8(truncatingIfNeeded: counter >> 16))
            input.append(UInt8(truncatingIfNeeded: counter >> 8))
            input.append(UInt8(truncatingIfNeeded: counter))
            output.append(hashSHA384(input))
            counter &+= 1
        }
        return Data(output.prefix(outputByteCount))
    }

    private static func hashSHA384(_ data: Data) -> Data {
        Data(CryptoKit.SHA384.hash(data: data))
    }
}
