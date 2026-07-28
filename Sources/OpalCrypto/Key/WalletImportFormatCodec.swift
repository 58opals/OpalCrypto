// WalletImportFormatCodec.swift

import Foundation

internal enum WalletImportFormatCodec {

    private static let mainnetVersion: UInt8 = 0x80

    internal static func encode(privateKey: Data, isCompressed: Bool) throws -> String {
        guard privateKey.count == 32 else {
            throw Error.invalidPrivateKeyLength(actual: privateKey.count)
        }
        guard StandardsForEfficientCryptography256k1CurveModel.Operation
            .isPrivateKeyData32BytesValid(privateKey) else {
            throw Error.invalidPrivateKey
        }

        return makeEncodedText(
            privateKeyData32Bytes: privateKey,
            isCompressed: isCompressed
        )
    }

    internal static func encode(
        privateKey: OpalCrypto.Secp256k1.PrivateKey,
        isCompressed: Bool
    ) -> String {
        makeEncodedText(
            privateKeyData32Bytes: privateKey.rawRepresentation,
            isCompressed: isCompressed
        )
    }

    internal static func decode(_ string: String) throws -> (privateKey: Data, isCompressed: Bool) {
        let payload: Data
        do {
            payload = try Base58CheckCodec.decode(
                string,
                minimumPayloadLength: 33,
                maximumPayloadLength: 34
            )
        } catch let error as Base58CheckCodec.Error {
            switch error {
            case .invalidBase58:
                throw Error.invalidBase58
            case .invalidChecksum:
                throw Error.invalidChecksum
            case .invalidPayloadLength(let actual):
                throw Error.invalidPayloadLength(actual: actual)
            case .payloadLengthExceedsMaximum(let maximum):
                throw Error.payloadLengthExceedsMaximum(maximum: maximum)
            }
        }

        guard let version = payload.first else {
            throw Error.invalidPayloadLength(actual: payload.count)
        }
        guard version == mainnetVersion else {
            throw Error.invalidVersion(actual: version)
        }

        switch payload.count {
        case 33:
            let privateKey = Data(payload.dropFirst())
            guard StandardsForEfficientCryptography256k1CurveModel.Operation
                .isPrivateKeyData32BytesValid(privateKey) else {
                throw Error.invalidPrivateKey
            }
            return (privateKey, false)
        case 34:
            let privateKey = Data(payload.dropFirst().dropLast())
            guard let marker = payload.last else {
                throw Error.invalidPayloadLength(actual: payload.count)
            }
            guard marker == 0x01 else {
                throw Error.invalidCompressionMarker(actual: marker)
            }
            guard StandardsForEfficientCryptography256k1CurveModel.Operation
                .isPrivateKeyData32BytesValid(privateKey) else {
                throw Error.invalidPrivateKey
            }
            return (privateKey, true)
        default:
            throw Error.invalidPayloadLength(actual: payload.count)
        }
    }

    private static func makeEncodedText(
        privateKeyData32Bytes: Data,
        isCompressed: Bool
    ) -> String {
        var payload = Data([mainnetVersion])
        payload.append(privateKeyData32Bytes)
        if isCompressed {
            payload.append(0x01)
        }
        return Base58CheckCodec.encode(payload: payload)
    }
}
