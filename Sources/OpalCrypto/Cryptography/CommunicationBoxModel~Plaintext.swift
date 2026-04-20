// CommunicationBoxModel~Plaintext.swift

import Foundation

extension CommunicationBoxModel {
    static func makePlaintext(
        message: Data,
        paddedPlaintextLength: Int?
    ) throws -> Data {
        let resolvedLength = try resolvePlaintextLength(
            messageByteCount: message.count,
            paddedPlaintextLength: paddedPlaintextLength
        )

        var plaintext = Data()
        plaintext.reserveCapacity(resolvedLength)
        plaintext.appendUInt32BigEndian(UInt32(message.count))
        plaintext.append(message)
        if resolvedLength > plaintext.count {
            plaintext.append(
                Data(repeating: 0x00, count: resolvedLength - plaintext.count)
            )
        }
        return plaintext
    }

    static func resolvePlaintextLength(
        messageByteCount: Int,
        paddedPlaintextLength: Int?
    ) throws -> Int {
        guard messageByteCount <= Int(UInt32.max) else {
            throw Error.messageTooLong(actual: messageByteCount)
        }

        let minimumLength = messageByteCount + 4
        if let paddedPlaintextLength {
            guard paddedPlaintextLength.isMultiple(of: 16) else {
                throw Error.paddedPlaintextLengthNotMultipleOf16(actual: paddedPlaintextLength)
            }
            guard paddedPlaintextLength >= minimumLength else {
                throw Error.invalidPaddedPlaintextLength(
                    minimum: minimumLength,
                    actual: paddedPlaintextLength
                )
            }
            return paddedPlaintextLength
        }

        return ((minimumLength + 15) / 16) * 16
    }
}
