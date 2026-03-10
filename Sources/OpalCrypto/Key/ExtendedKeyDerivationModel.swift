// ExtendedKeyDerivationModel.swift

import Foundation

internal enum ExtendedKeyDerivationModel {
    internal enum Error: Swift.Error, Equatable {
        case invalidSeed
        case invalidKeyKind
        case hardenedDerivationRequiresPrivateKey
        case depthOverflow
        case invalidDerivedKey
    }

    private static let hardenedMask: UInt32 = 0x8000_0000

    internal static func makeRootPrivateKey(seed: Data) throws -> ExtendedKeyPayloadModel {
        guard !seed.isEmpty else {
            throw Error.invalidSeed
        }
        let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.hash(
            seed,
            key: Data("Bitcoin seed".utf8)
        )
        return try ExtendedKeyPayloadModel(
            kind: .privateKey,
            depth: 0,
            parentFingerprint: Data(repeating: 0x00, count: 4),
            childIndex: 0,
            chainCode: Data(digest.suffix(32)),
            keyData: Data(digest.prefix(32))
        )
    }

    internal static func makePublicKey(
        from privateKeyPayload: ExtendedKeyPayloadModel
    ) throws -> ExtendedKeyPayloadModel {
        guard privateKeyPayload.kind == .privateKey else {
            throw Error.invalidKeyKind
        }

        return try ExtendedKeyPayloadModel(
            kind: .publicKey,
            depth: privateKeyPayload.depth,
            parentFingerprint: privateKeyPayload.parentFingerprint,
            childIndex: privateKeyPayload.childIndex,
            chainCode: privateKeyPayload.chainCode,
            keyData: compressedPublicKey(from: privateKeyPayload)
        )
    }

    internal static func derivePrivateChild(
        from privateKeyPayload: ExtendedKeyPayloadModel,
        index: UInt32
    ) throws -> ExtendedKeyPayloadModel {
        guard privateKeyPayload.kind == .privateKey else {
            throw Error.invalidKeyKind
        }
        guard privateKeyPayload.depth < UInt8.max else {
            throw Error.depthOverflow
        }

        let parentPublicKey = try compressedPublicKey(from: privateKeyPayload)
        var digestInput = Data()
        if isHardened(index) {
            digestInput.append(0x00)
            digestInput.append(privateKeyPayload.keyData)
        } else {
            digestInput.append(parentPublicKey)
        }
        digestInput.appendUInt32BigEndian(index)

        let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.hash(
            digestInput,
            key: privateKeyPayload.chainCode
        )
        let tweak = Data(digest.prefix(32))
        let childChainCode = Data(digest.suffix(32))

        let childPrivateKey: Data
        do {
            childPrivateKey = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .tweakAddPrivateKeyData32Bytes(
                    privateKeyPayload.keyData,
                    tweakData32Bytes: tweak
                )
        } catch {
            throw Error.invalidDerivedKey
        }

        return try ExtendedKeyPayloadModel(
            kind: .privateKey,
            depth: privateKeyPayload.depth + 1,
            parentFingerprint: fingerprint(publicKey: parentPublicKey),
            childIndex: index,
            chainCode: childChainCode,
            keyData: childPrivateKey
        )
    }

    internal static func derivePublicChild(
        from publicKeyPayload: ExtendedKeyPayloadModel,
        index: UInt32
    ) throws -> ExtendedKeyPayloadModel {
        guard publicKeyPayload.kind == .publicKey else {
            throw Error.invalidKeyKind
        }
        guard !isHardened(index) else {
            throw Error.hardenedDerivationRequiresPrivateKey
        }
        guard publicKeyPayload.depth < UInt8.max else {
            throw Error.depthOverflow
        }

        var digestInput = Data()
        digestInput.append(publicKeyPayload.keyData)
        digestInput.appendUInt32BigEndian(index)
        let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.hash(
            digestInput,
            key: publicKeyPayload.chainCode
        )

        let tweak = Data(digest.prefix(32))
        let childChainCode = Data(digest.suffix(32))
        let childPublicKey: Data
        do {
            childPublicKey = try StandardsForEfficientCryptography256k1CurveModel.Operation.tweakAddPublicKey(
                publicKeyPayload.keyData,
                tweakData32Bytes: tweak,
                format: .compressed
            )
        } catch {
            throw Error.invalidDerivedKey
        }

        return try ExtendedKeyPayloadModel(
            kind: .publicKey,
            depth: publicKeyPayload.depth + 1,
            parentFingerprint: fingerprint(publicKey: publicKeyPayload.keyData),
            childIndex: index,
            chainCode: childChainCode,
            keyData: childPublicKey
        )
    }

    private static func compressedPublicKey(from payload: ExtendedKeyPayloadModel) throws -> Data {
        guard payload.kind == .privateKey else {
            throw Error.invalidKeyKind
        }
        do {
            return try StandardsForEfficientCryptography256k1CurveModel.Operation.derivePublicKey(
                fromPrivateKeyData32Bytes: payload.keyData,
                format: .compressed
            )
        } catch {
            throw Error.invalidDerivedKey
        }
    }

    private static func fingerprint(publicKey: Data) -> Data {
        Data(SecureHash160Model.hash(publicKey).prefix(4))
    }

    private static func isHardened(_ index: UInt32) -> Bool {
        (index & hardenedMask) != 0
    }
}
