// ParsedPublicKeyModel.swift

import Foundation

struct ParsedPublicKeyModel: Sendable, Equatable {
    enum Error: Swift.Error, Equatable {
        case invalidPublicKeyLength(actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
    }

    let compressedPublicKeyData: Data
    let affinePoint: AffinePointModel
    let fingerprintData4Bytes: Data

    init(publicKeyData: Data) throws {
        let affinePoint: AffinePointModel
        do {
            affinePoint = try PublicKeyParserModel.parsePublicKey(publicKeyData)
        } catch PublicKeyParserModel.Error.invalidLength(let actual) {
            throw Error.invalidPublicKeyLength(actual: actual)
        } catch PublicKeyParserModel.Error.invalidPrefix(let byte) {
            throw Error.invalidPublicKeyPrefix(actual: byte)
        } catch {
            throw Error.invalidPublicKey
        }

        let compressedPublicKeyData = if publicKeyData.count == 33 {
            publicKeyData
        } else {
            affinePoint.encodeCompressed33()
        }
        self.init(
            affinePoint: affinePoint,
            compressedPublicKeyData: compressedPublicKeyData
        )
    }

    init(affinePoint: AffinePointModel) {
        let compressedPublicKeyData = affinePoint.encodeCompressed33()
        self.init(
            affinePoint: affinePoint,
            compressedPublicKeyData: compressedPublicKeyData
        )
    }

    init(
        affinePoint: AffinePointModel,
        compressedPublicKeyData: Data
    ) {
        self.compressedPublicKeyData = compressedPublicKeyData
        self.affinePoint = affinePoint
        self.fingerprintData4Bytes = Data(
            SecureHash160Model.hash(compressedPublicKeyData).prefix(4)
        )
    }

    static func == (
        lhs: ParsedPublicKeyModel,
        rhs: ParsedPublicKeyModel
    ) -> Bool {
        lhs.compressedPublicKeyData == rhs.compressedPublicKeyData
    }
}
