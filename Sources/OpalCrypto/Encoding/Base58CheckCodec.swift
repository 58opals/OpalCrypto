// Base58CheckCodec.swift

import Foundation
import OpalDiagnostics

internal enum Base58CheckCodec {

    internal static func encode(payload: Data) -> String {
        let checksum = SecureHash256Model.hash(payload).prefix(4)
        return Base58EncodingCodec.encode(payload + checksum)
    }

    internal static func decode(
        _ string: String,
        minimumPayloadLength: Int = 1,
        maximumPayloadLength: Int
    ) throws -> Data {
        let minimumPayloadLength = max(0, minimumPayloadLength)
        guard maximumPayloadLength >= minimumPayloadLength,
              maximumPayloadLength <= Int.max - 4 else {
            let error = Error.invalidPayloadLength(actual: 0)
            recordDecodeFailure(
                error,
                inputCharacterCount: string.count,
                minimumPayloadLength: minimumPayloadLength,
                maximumPayloadLength: maximumPayloadLength
            )
            throw error
        }
        func recordFailure(_ error: Error) {
            recordDecodeFailure(
                error,
                inputCharacterCount: string.count,
                minimumPayloadLength: minimumPayloadLength,
                maximumPayloadLength: maximumPayloadLength
            )
        }

        let decoded: Data
        do {
            decoded = try Base58EncodingCodec.decode(
                string,
                maximumDecodedByteCount: maximumPayloadLength + 4
            )
        } catch Base58EncodingCodec.Error.invalidCharacterFound {
            recordFailure(.invalidBase58)
            throw Error.invalidBase58
        } catch Base58EncodingCodec.Error.decodedDataExceedsMaximumByteCount {
            let error = Error.payloadLengthExceedsMaximum(
                maximum: maximumPayloadLength
            )
            recordFailure(error)
            throw error
        } catch Base58EncodingCodec.Error.invalidMaximumDecodedByteCount {
            let error = Error.invalidPayloadLength(actual: 0)
            recordFailure(error)
            throw error
        }
        guard decoded.count >= 4, decoded.count - 4 >= minimumPayloadLength else {
            let error = Error.invalidPayloadLength(actual: max(0, decoded.count - 4))
            recordFailure(error)
            throw error
        }

        let payload = decoded.dropLast(4)
        let checksum = decoded.suffix(4)
        let expectedChecksum = SecureHash256Model.hash(payload).prefix(4)
        guard Data(checksum).constantTimeEquals(expectedChecksum) else {
            recordFailure(.invalidChecksum)
            throw Error.invalidChecksum
        }

        return Data(payload)
    }

    private static func recordDecodeFailure(
        _ error: Error,
        inputCharacterCount: Int,
        minimumPayloadLength: Int,
        maximumPayloadLength: Int
    ) {
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.encoding).record(
            event: OpalDiagnostics.Event.base58CheckDecodeFailed,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.base58CheckDecodeFailed),
            fields: [
                OpalDiagnostics.Field.operationField("base58check_decode"),
                OpalDiagnostics.Field.formatField("base58check"),
                OpalDiagnostics.Field.publicField("input_character_count", inputCharacterCount),
                OpalDiagnostics.Field.publicField("minimum_payload_length", minimumPayloadLength),
                OpalDiagnostics.Field.publicField("maximum_payload_length", maximumPayloadLength)
            ] + OpalDiagnostics.Field.errorFields(error)
        )
    }
}
