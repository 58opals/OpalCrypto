// ParsedPublicKeyModel.swift

import Foundation

struct ParsedPublicKeyModel: Sendable, Equatable {

    let compressedPublicKeyData: Data
    let affinePoint: AffinePointModel
    let fingerprintUInt32BigEndian: UInt32

    var fingerprintData4Bytes: Data {
        Data(bigEndianUInt32: fingerprintUInt32BigEndian)
    }

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
            Data(publicKeyData)
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
        self.fingerprintUInt32BigEndian = SecureHash160Model
            .hash(compressedPublicKeyData)
            .uint32BigEndian(at: 0)
    }

    static func == (
        lhs: ParsedPublicKeyModel,
        rhs: ParsedPublicKeyModel
    ) -> Bool {
        lhs.compressedPublicKeyData == rhs.compressedPublicKeyData
    }
}
