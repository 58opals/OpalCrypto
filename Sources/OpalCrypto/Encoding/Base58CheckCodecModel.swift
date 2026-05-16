// Base58CheckCodecModel.swift

import Foundation

internal enum Base58CheckCodecModel {

    internal static func encode(payload: Data) -> String {
        let checksum = SecureHash256Model.hash(payload).prefix(4)
        return Base58EncodingModel.encode(payload + checksum)
    }

    internal static func decode(_ string: String, minimumPayloadLength: Int = 1) throws -> Data {
        guard let decoded = Base58EncodingModel.decode(string) else {
            recordDecodeFailure(
                .invalidBase58,
                inputCharacterCount: string.count,
                minimumPayloadLength: minimumPayloadLength
            )
            throw Error.invalidBase58
        }
        guard decoded.count >= minimumPayloadLength + 4 else {
            let error = Error.invalidPayloadLength(actual: max(0, decoded.count - 4))
            recordDecodeFailure(
                error,
                inputCharacterCount: string.count,
                minimumPayloadLength: minimumPayloadLength
            )
            throw error
        }

        let payload = decoded.dropLast(4)
        let checksum = decoded.suffix(4)
        let expectedChecksum = SecureHash256Model.hash(payload).prefix(4)
        guard Data(checksum).constantTimeEquals(expectedChecksum) else {
            recordDecodeFailure(
                .invalidChecksum,
                inputCharacterCount: string.count,
                minimumPayloadLength: minimumPayloadLength
            )
            throw Error.invalidChecksum
        }

        return Data(payload)
    }

    private static func recordDecodeFailure(
        _ error: Error,
        inputCharacterCount: Int,
        minimumPayloadLength: Int
    ) {
        OpalCryptoDiagnostics.record(
            OpalCryptoDiagnostics.Event.base58CheckDecodeFailed,
            category: OpalCryptoDiagnostics.Category.encoding,
            fields: [
                OpalCryptoDiagnostics.operationField("base58check_decode"),
                OpalCryptoDiagnostics.publicField("input_character_count", inputCharacterCount),
                OpalCryptoDiagnostics.publicField("minimum_payload_length", minimumPayloadLength)
            ] + OpalCryptoDiagnostics.errorFields(error)
        )
    }
}
