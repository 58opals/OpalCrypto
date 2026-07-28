// ExtendedKeyDerivationModel.swift

import Foundation

internal enum ExtendedKeyDerivationModel {
    private static let hardenedMask: UInt32 = 0x8000_0000

    internal static func makeRootPrivateKey(seed: Data) throws -> ExtendedKeyPayloadModel {
        guard (16...64).contains(seed.count) else {
            throw Error.invalidSeed
        }
        let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.hash(
            seed,
            key: Data("Bitcoin seed".utf8)
        )
        let chainCodeStartIndex = digest.index(digest.startIndex, offsetBy: 32)
        do {
            return try ExtendedKeyPayloadModel(
                kind: .privateKey,
                depth: 0,
                parentFingerprintUInt32BigEndian: 0,
                childIndex: 0,
                chainCode: Data(digest[chainCodeStartIndex..<digest.endIndex]),
                keyData: Data(digest[digest.startIndex..<chainCodeStartIndex])
            )
        } catch is ExtendedKeyPayloadModel.Error {
            throw Error.invalidDerivedKey
        }
    }

    internal static func makePublicKey(
        from privateKeyPayload: ExtendedKeyPayloadModel
    ) throws -> ExtendedKeyPayloadModel {
        guard privateKeyPayload.kind == .privateKey else {
            throw Error.invalidKeyKind
        }
        let parsedPrivateKeyModel: ParsedPrivateKeyModel
        do {
            parsedPrivateKeyModel = try ParsedPrivateKeyModel(
                privateKeyData32Bytes: privateKeyPayload.keyData
            )
        } catch {
            throw Error.invalidDerivedKey
        }

        return ExtendedKeyPayloadModel.makeTrustedDerivedPublicKey(
            depth: privateKeyPayload.depth,
            parentFingerprintUInt32BigEndian: privateKeyPayload.parentFingerprintUInt32BigEndian,
            childIndex: privateKeyPayload.childIndex,
            chainCode: privateKeyPayload.chainCode,
            publicKeyData33Bytes: parsedPrivateKeyModel.compressedPublicKeyData
        )
    }
    static func isHardened(_ index: UInt32) -> Bool {
        (index & hardenedMask) != 0
    }
}
