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
        let parentCompressedPublicKeyFingerprintData4Bytes = fingerprint(
            publicKey: parentCompressedPublicKeyData
        )
        return try derivePrivateChildMaterial(
            from: privateKeyPayload,
            parentCompressedPublicKeyData: parentCompressedPublicKeyData,
            parentCompressedPublicKeyFingerprintData4Bytes:
                parentCompressedPublicKeyFingerprintData4Bytes,
            index: index
        ).payload
    }

    internal static func derivePrivateChildMaterial(
        from privateKeyPayload: ExtendedKeyPayloadModel,
        parentCompressedPublicKeyData: Data,
        parentCompressedPublicKeyFingerprintData4Bytes: Data,
        index: UInt32
    ) throws -> (
        payload: ExtendedKeyPayloadModel,
        compressedPublicKeyData: Data,
        compressedPublicKeyFingerprintData4Bytes: Data
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
            parentFingerprint: parentCompressedPublicKeyFingerprintData4Bytes,
            childIndex: index,
            chainCode: childChainCode,
            keyData: childPrivateKey
        )
        let childCompressedPublicKeyData = try compressedPublicKey(from: childPayload)
        let childCompressedPublicKeyFingerprintData4Bytes = fingerprint(
            publicKey: childCompressedPublicKeyData
        )
        return (
            childPayload,
            childCompressedPublicKeyData,
            childCompressedPublicKeyFingerprintData4Bytes
        )
    }

    internal static func derivePublicChild(
        from publicKeyPayload: ExtendedKeyPayloadModel,
        index: UInt32
    ) throws -> ExtendedKeyPayloadModel {
        let parsedPublicKeyModel = try StandardsForEfficientCryptography256k1CurveModel
            .Operation.makeParsedPublicKey(publicKey: publicKeyPayload.keyData)
        return try derivePublicChildMaterial(
            from: publicKeyPayload,
            parsedPublicKeyModel: parsedPublicKeyModel,
            index: index
        ).payload
    }

    internal static func derivePublicChildMaterial(
        from publicKeyPayload: ExtendedKeyPayloadModel,
        parsedPublicKeyModel: ParsedPublicKeyModel,
        index: UInt32
    ) throws -> (
        payload: ExtendedKeyPayloadModel,
        parsedPublicKeyModel: ParsedPublicKeyModel
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
        digestInput.reserveCapacity(37)
        digestInput.append(parsedPublicKeyModel.compressedPublicKeyData)
        digestInput.appendUInt32BigEndian(index)
        let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.hash(
            digestInput,
            key: publicKeyPayload.chainCode
        )

        let chainCodeStartIndex = digest.index(digest.startIndex, offsetBy: 32)
        let tweak = digest[digest.startIndex..<chainCodeStartIndex]
        let childChainCode = Data(digest[chainCodeStartIndex..<digest.endIndex])
        let childParsedPublicKeyModel: ParsedPublicKeyModel
        do {
            let tweakScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .parseTweakScalar(contiguousBytes32: tweak, requireNonZero: false)
            childParsedPublicKeyModel = try StandardsForEfficientCryptography256k1CurveModel
                .Operation.tweakAddParsedPublicKey(
                    parsedPublicKeyModel,
                    tweakScalar: tweakScalar
                )
        } catch {
            throw Error.invalidDerivedKey
        }

        let childPayload = try ExtendedKeyPayloadModel(
            kind: .publicKey,
            depth: publicKeyPayload.depth + 1,
            parentFingerprint: parsedPublicKeyModel.fingerprintData4Bytes,
            childIndex: index,
            chainCode: childChainCode,
            keyData: childParsedPublicKeyModel.compressedPublicKeyData
        )
        return (childPayload, childParsedPublicKeyModel)
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
