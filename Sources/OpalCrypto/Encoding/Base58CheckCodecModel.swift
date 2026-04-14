// Base58CheckCodecModel.swift

import Foundation

internal enum Base58CheckCodecModel {

    internal static func encode(payload: Data) -> String {
        let checksum = SecureHash256Model.hash(payload).prefix(4)
        return Base58EncodingModel.encode(payload + checksum)
    }

    internal static func decode(_ string: String, minimumPayloadLength: Int = 1) throws -> Data {
        guard let decoded = Base58EncodingModel.decode(string) else {
            throw Error.invalidBase58
        }
        guard decoded.count >= minimumPayloadLength + 4 else {
            throw Error.invalidPayloadLength(actual: decoded.count)
        }

        let payload = decoded.dropLast(4)
        let checksum = decoded.suffix(4)
        let expectedChecksum = SecureHash256Model.hash(payload).prefix(4)
        guard Data(checksum) == expectedChecksum else {
            throw Error.invalidChecksum
        }

        return Data(payload)
    }
}
