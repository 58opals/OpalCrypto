// CommunicationBoxModel~Plaintext.swift

import Foundation

extension CommunicationBoxModel {
    static func makePlaintext(
        message: Data,
        resolvedPlaintextLength: Int
    ) throws -> Data {
        var plaintext = Data()
        plaintext.reserveCapacity(resolvedPlaintextLength)
        plaintext.appendUInt32BigEndian(UInt32(message.count))
        plaintext.append(message)
        if resolvedPlaintextLength > plaintext.count {
            plaintext.append(
                contentsOf: repeatElement(
                    UInt8.zero,
                    count: resolvedPlaintextLength - plaintext.count
                )
            )
        }
        return plaintext
    }

    static func resolvePlaintextLength(
        messageByteCount: Int,
        paddedPlaintextLength: Int?
    ) throws -> Int {
        guard messageByteCount >= 0 else {
            throw Error.invalidMessageLength(actual: messageByteCount)
        }
        guard messageByteCount <= Int(UInt32.max) else {
            throw Error.messageTooLong(actual: messageByteCount)
        }

        let (minimumLength, minimumLengthOverflow) = messageByteCount.addingReportingOverflow(4)
        guard !minimumLengthOverflow else {
            throw Error.ciphertextByteCountOverflow
        }
        if let paddedPlaintextLength {
            guard paddedPlaintextLength >= minimumLength else {
                throw Error.invalidPaddedPlaintextLength(
                    minimum: minimumLength,
                    actual: paddedPlaintextLength
                )
            }
            guard paddedPlaintextLength.isMultiple(of: 16) else {
                throw Error.paddedPlaintextLengthNotMultipleOf16(actual: paddedPlaintextLength)
            }
            return paddedPlaintextLength
        }

        let (lengthBeforeRounding, roundingOverflow) = minimumLength.addingReportingOverflow(15)
        guard !roundingOverflow else {
            throw Error.ciphertextByteCountOverflow
        }
        return (lengthBeforeRounding / 16) * 16
    }

    static func preflightCiphertextByteCount(
        messageByteCount: Int,
        paddedPlaintextLength: Int?,
        maximumCiphertextByteCount: Int
    ) throws -> (plaintextByteCount: Int, ciphertextByteCount: Int) {
        let plaintextByteCount = try resolvePlaintextLength(
            messageByteCount: messageByteCount,
            paddedPlaintextLength: paddedPlaintextLength
        )
        let (ciphertextByteCount, overflow) = plaintextByteCount.addingReportingOverflow(
            ciphertextEnvelopeOverheadByteCount
        )
        guard !overflow else {
            throw Error.ciphertextByteCountOverflow
        }
        try validateCiphertextByteCount(
            ciphertextByteCount,
            maximumCiphertextByteCount: maximumCiphertextByteCount
        )
        return (plaintextByteCount, ciphertextByteCount)
    }
}
