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
        guard (16...64).contains(seed.count) else {
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
            parentFingerprintUInt32BigEndian: 0,
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

    internal static func derivePrivateChild(
        from privateKeyPayload: ExtendedKeyPayloadModel,
        index: UInt32
    ) throws -> ExtendedKeyPayloadModel {
        let parsedPrivateKeyModel: ParsedPrivateKeyModel
        do {
            parsedPrivateKeyModel = try ParsedPrivateKeyModel(
                privateKeyData32Bytes: privateKeyPayload.keyData
            )
        } catch {
            throw Error.invalidDerivedKey
        }
        return try derivePrivateChildMaterial(
            from: privateKeyPayload,
            parsedPrivateKeyModel: parsedPrivateKeyModel,
            index: index
        ).payload
    }

    internal static func derivePrivateChildMaterial(
        from privateKeyPayload: ExtendedKeyPayloadModel,
        parsedPrivateKeyModel: ParsedPrivateKeyModel,
        index: UInt32
    ) throws -> (
        payload: ExtendedKeyPayloadModel,
        parsedPrivateKeyModel: ParsedPrivateKeyModel
    ) {
        guard privateKeyPayload.kind == .privateKey else {
            throw Error.invalidKeyKind
        }
        guard privateKeyPayload.depth < UInt8.max else {
            throw Error.depthOverflow
        }

        let digestInput = makePrivateChildDigestInput(
            parentCompressedPublicKeyData: parsedPrivateKeyModel.compressedPublicKeyData,
            parentPrivateKeyData32Bytes: privateKeyPayload.keyData,
            index: index
        )

        let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.hash(
            digestInput,
            key: privateKeyPayload.chainCode
        )
        let chainCodeStartIndex = digest.index(digest.startIndex, offsetBy: 32)
        let tweak = digest[digest.startIndex..<chainCodeStartIndex]
        let childChainCode = Data(digest[chainCodeStartIndex..<digest.endIndex])

        let childPrivateKeyScalar: ScalarModel
        do {
            let tweakScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
                .parseTweakScalar(contiguousBytes32: tweak, requireNonZero: false)
            let derivedScalar = parsedPrivateKeyModel.scalar.addModN(tweakScalar)
            guard !derivedScalar.isZero else {
                throw Error.invalidDerivedKey
            }
            childPrivateKeyScalar = derivedScalar
        } catch {
            throw Error.invalidDerivedKey
        }

        let childPrivateKey = childPrivateKeyScalar.data32Bytes
        let childParsedPrivateKeyModel: ParsedPrivateKeyModel
        do {
            childParsedPrivateKeyModel = try ParsedPrivateKeyModel(
                trustedScalar: childPrivateKeyScalar
            )
        } catch {
            throw Error.invalidDerivedKey
        }

        let childPayload = ExtendedKeyPayloadModel.makeTrustedDerivedPrivateKey(
            depth: privateKeyPayload.depth + 1,
            parentFingerprintUInt32BigEndian:
                parsedPrivateKeyModel.compressedPublicKeyFingerprintUInt32BigEndian,
            childIndex: index,
            chainCode: childChainCode,
            privateKeyData32Bytes: childPrivateKey
        )
        return (childPayload, childParsedPrivateKeyModel)
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

        let digestInput = makePublicChildDigestInput(
            parentCompressedPublicKeyData: parsedPublicKeyModel.compressedPublicKeyData,
            index: index
        )
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

        let childPayload = ExtendedKeyPayloadModel.makeTrustedDerivedPublicKey(
            depth: publicKeyPayload.depth + 1,
            parentFingerprintUInt32BigEndian: parsedPublicKeyModel.fingerprintUInt32BigEndian,
            childIndex: index,
            chainCode: childChainCode,
            publicKeyData33Bytes: childParsedPublicKeyModel.compressedPublicKeyData
        )
        return (childPayload, childParsedPublicKeyModel)
    }

    private static func makePrivateChildDigestInput(
        parentCompressedPublicKeyData: Data,
        parentPrivateKeyData32Bytes: Data,
        index: UInt32
    ) -> Data {
        precondition(parentCompressedPublicKeyData.count == 33)
        precondition(parentPrivateKeyData32Bytes.count == 32)

        if isHardened(index) {
            var digestInput = Data(count: 37)
            digestInput.withUnsafeMutableBytes { rawBuffer in
                let destination = rawBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                destination[0] = 0x00
                parentPrivateKeyData32Bytes.copyBytes(
                    to: destination.advanced(by: 1),
                    count: 32
                )
                writeUInt32BigEndian(index, to: destination.advanced(by: 33))
            }
            return digestInput
        }

        return makePublicChildDigestInput(
            parentCompressedPublicKeyData: parentCompressedPublicKeyData,
            index: index
        )
    }

    private static func makePublicChildDigestInput(
        parentCompressedPublicKeyData: Data,
        index: UInt32
    ) -> Data {
        precondition(parentCompressedPublicKeyData.count == 33)

        var digestInput = Data(count: 37)
        digestInput.withUnsafeMutableBytes { rawBuffer in
            let destination = rawBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self)
            parentCompressedPublicKeyData.copyBytes(to: destination, count: 33)
            writeUInt32BigEndian(index, to: destination.advanced(by: 33))
        }
        return digestInput
    }

    private static func writeUInt32BigEndian(
        _ value: UInt32,
        to destination: UnsafeMutablePointer<UInt8>
    ) {
        destination[0] = UInt8((value >> 24) & 0xff)
        destination[1] = UInt8((value >> 16) & 0xff)
        destination[2] = UInt8((value >> 8) & 0xff)
        destination[3] = UInt8(value & 0xff)
    }

    private static func isHardened(_ index: UInt32) -> Bool {
        (index & hardenedMask) != 0
    }
}
