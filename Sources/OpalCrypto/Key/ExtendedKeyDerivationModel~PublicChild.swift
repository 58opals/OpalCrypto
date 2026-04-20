// ExtendedKeyDerivationModel~PublicChild.swift

import Foundation

extension ExtendedKeyDerivationModel {
    internal static func derivePublicChild(
        from publicKeyPayload: ExtendedKeyPayloadModel,
        index: UInt32
    ) throws -> ExtendedKeyPayloadModel {
        guard publicKeyPayload.kind == .publicKey else {
            throw Error.invalidKeyKind
        }
        let parsedPublicKeyModel: ParsedPublicKeyModel
        do {
            parsedPublicKeyModel = try StandardsForEfficientCryptography256k1CurveModel
                .Operation.makeParsedPublicKey(publicKey: publicKeyPayload.keyData)
        } catch {
            throw Error.invalidDerivedKey
        }
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
}
