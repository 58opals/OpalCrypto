// ExtendedKeyDerivationModel~ExplicitChild.swift

import Foundation

extension ExtendedKeyDerivationModel {
    static func deriveNonHardenedPublicChild(
        from parentPublicKey: ParsedPublicKeyModel,
        chainCode: Data,
        index: UInt32
    ) throws -> ParsedPublicKeyModel {
        let tweakScalar = try deriveNonHardenedChildTweak(
            parentCompressedPublicKeyData:
                parentPublicKey.compressedPublicKeyData,
            chainCode: chainCode,
            index: index
        )
        return try derivePublicChild(
            from: parentPublicKey,
            tweakScalar: tweakScalar
        )
    }

    static func deriveNonHardenedPrivateChild(
        from parentSigningKey: ParsedPrivateKeyModel,
        chainCode: Data,
        index: UInt32
    ) throws -> ParsedPrivateKeyModel {
        let tweakScalar = try deriveNonHardenedChildTweak(
            parentCompressedPublicKeyData:
                parentSigningKey.compressedPublicKeyData,
            chainCode: chainCode,
            index: index
        )
        let childScalar = HardenedScalarArithmeticModel.addModN(
            parentSigningKey.scalar,
            tweakScalar
        )
        guard !childScalar.isZero else {
            throw Error.invalidDerivedKey
        }

        let childPublicKey = try derivePublicChild(
            from: parentSigningKey.parsedPublicKeyModel,
            tweakScalar: tweakScalar
        )
        return ParsedPrivateKeyModel(
            validatedPrivateKeyScalar: childScalar,
            correspondingParsedPublicKeyModel: childPublicKey
        )
    }

    private static func derivePublicChild(
        from parentPublicKey: ParsedPublicKeyModel,
        tweakScalar: ScalarModel
    ) throws -> ParsedPublicKeyModel {
        let tweakPoint = HardenedScalarMultiplicationModel.multiply(
            tweakScalar,
            by: ScalarMultiplicationModel.generator
        )
        let parentPoint = CompleteProjectivePointModel(
            affinePoint: parentPublicKey.affinePoint
        )
        guard let childPoint = parentPoint.add(tweakPoint).affinePoint else {
            throw Error.invalidDerivedKey
        }
        return ParsedPublicKeyModel(affinePoint: childPoint)
    }

    private static func deriveNonHardenedChildTweak(
        parentCompressedPublicKeyData: Data,
        chainCode: Data,
        index: UInt32
    ) throws -> ScalarModel {
        guard !isHardened(index) else {
            throw Error.hardenedDerivationRequiresPrivateKey
        }
        let digestInput = makePublicChildDigestInput(
            parentCompressedPublicKeyData: parentCompressedPublicKeyData,
            index: index
        )
        let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model
            .hash(digestInput, key: chainCode)
        do {
            return try StandardsForEfficientCryptography256k1CurveModel
                .Operation.parseTweakScalar(
                    contiguousBytes32: digest.prefix(32),
                    requireNonZero: false
                )
        } catch {
            throw Error.invalidDerivedKey
        }
    }
}
