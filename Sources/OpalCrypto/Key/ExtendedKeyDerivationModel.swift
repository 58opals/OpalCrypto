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
        let chainCodeStartIndex = digest.index(digest.startIndex, offsetBy: 32)
        return try ExtendedKeyPayloadModel(
            kind: .privateKey,
            depth: 0,
            parentFingerprint: Data(repeating: 0x00, count: 4),
            childIndex: 0,
            chainCode: Data(digest[chainCodeStartIndex..<digest.endIndex]),
            keyData: Data(digest[digest.startIndex..<chainCodeStartIndex])
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
        let parentCompressedPublicKeyData = try compressedPublicKey(from: privateKeyPayload)
        return try derivePrivateChildMaterial(
            from: privateKeyPayload,
            parentCompressedPublicKeyData: parentCompressedPublicKeyData,
            index: index
        ).payload
    }

    internal static func derivePrivateChildMaterial(
        from privateKeyPayload: ExtendedKeyPayloadModel,
        parentCompressedPublicKeyData: Data,
        index: UInt32
    ) throws -> (
        payload: ExtendedKeyPayloadModel,
        compressedPublicKeyData: Data
    ) {
        guard privateKeyPayload.kind == .privateKey else {
            throw Error.invalidKeyKind
        }
        guard privateKeyPayload.depth < UInt8.max else {
            throw Error.depthOverflow
        }

        var digestInput = Data()
        if isHardened(index) {
            digestInput.append(0x00)
            digestInput.append(privateKeyPayload.keyData)
        } else {
            digestInput.append(parentCompressedPublicKeyData)
        }
        digestInput.appendUInt32BigEndian(index)

        let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.hash(
            digestInput,
            key: privateKeyPayload.chainCode
        )
        let chainCodeStartIndex = digest.index(digest.startIndex, offsetBy: 32)
        let tweak = digest[digest.startIndex..<chainCodeStartIndex]
        let childChainCode = Data(digest[chainCodeStartIndex..<digest.endIndex])

        let childPrivateKey: Data
        do {
            let privateKeyScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .parsePrivateKeyScalar(privateKeyPayload.keyData, requireNonZero: true)
            let tweakScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .parseTweakScalar(contiguousBytes32: tweak, requireNonZero: false)
            let derivedScalar = privateKeyScalar.addModN(tweakScalar)
            guard !derivedScalar.isZero else {
                throw Error.invalidDerivedKey
            }
            childPrivateKey = derivedScalar.data32Bytes
        } catch {
            throw Error.invalidDerivedKey
        }

        let childPayload = try ExtendedKeyPayloadModel(
            kind: .privateKey,
            depth: privateKeyPayload.depth + 1,
            parentFingerprint: fingerprint(publicKey: parentCompressedPublicKeyData),
            childIndex: index,
            chainCode: childChainCode,
            keyData: childPrivateKey
        )
        let childCompressedPublicKeyData = try compressedPublicKey(from: childPayload)
        return (childPayload, childCompressedPublicKeyData)
    }

    internal static func derivePublicChild(
        from publicKeyPayload: ExtendedKeyPayloadModel,
        index: UInt32
    ) throws -> ExtendedKeyPayloadModel {
        let verificationKeyModel = try StandardsForEfficientCryptography256k1CurveModel
            .Operation.makeVerificationKey(publicKey: publicKeyPayload.keyData)
        return try derivePublicChildMaterial(
            from: publicKeyPayload,
            verificationKeyModel: verificationKeyModel,
            index: index
        ).payload
    }

    internal static func derivePublicChildMaterial(
        from publicKeyPayload: ExtendedKeyPayloadModel,
        verificationKeyModel: VerificationKeyModel,
        index: UInt32
    ) throws -> (
        payload: ExtendedKeyPayloadModel,
        verificationKeyModel: VerificationKeyModel
    ) {
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
        digestInput.append(verificationKeyModel.compressedPublicKeyData)
        digestInput.appendUInt32BigEndian(index)
        let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.hash(
            digestInput,
            key: publicKeyPayload.chainCode
        )

        let chainCodeStartIndex = digest.index(digest.startIndex, offsetBy: 32)
        let tweak = digest[digest.startIndex..<chainCodeStartIndex]
        let childChainCode = Data(digest[chainCodeStartIndex..<digest.endIndex])
        let childVerificationKeyModel: VerificationKeyModel
        do {
            let tweakScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .parseTweakScalar(contiguousBytes32: tweak, requireNonZero: false)
            childVerificationKeyModel = try StandardsForEfficientCryptography256k1CurveModel
                .Operation.tweakAddVerificationKey(
                    verificationKeyModel,
                    tweakScalar: tweakScalar
                )
        } catch {
            throw Error.invalidDerivedKey
        }

        let childPayload = try ExtendedKeyPayloadModel(
            kind: .publicKey,
            depth: publicKeyPayload.depth + 1,
            parentFingerprint: fingerprint(
                publicKey: verificationKeyModel.compressedPublicKeyData
            ),
            childIndex: index,
            chainCode: childChainCode,
            keyData: childVerificationKeyModel.compressedPublicKeyData
        )
        return (childPayload, childVerificationKeyModel)
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
