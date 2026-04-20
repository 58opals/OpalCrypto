// ExtendedKeyDerivationModel~PrivateChild.swift

import Foundation

extension ExtendedKeyDerivationModel {
    internal static func derivePrivateChild(
        from privateKeyPayload: ExtendedKeyPayloadModel,
        index: UInt32
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
}
