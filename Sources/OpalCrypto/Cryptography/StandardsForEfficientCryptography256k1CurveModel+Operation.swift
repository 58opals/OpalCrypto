// StandardsForEfficientCryptography256k1CurveModel+Operation.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel {
    internal enum Operation {

        internal static var curveOrderN: Data {
            StandardsForEfficientCryptography256k1CurveModel.Constant.n.data32Bytes
        }

        internal static func isPrivateKeyData32BytesValid(_ privateKeyData32Bytes: Data) -> Bool {
            (try? ScalarModel(data32: privateKeyData32Bytes, requireNonZero: true)) != nil
        }

        internal static func derivePublicKey(
            fromPrivateKeyData32Bytes privateKeyData32Bytes: Data,
            format: PublicKeyFormat = .compressed
        ) throws -> Data {
            let privateKeyScalar = try parsePrivateKeyScalar(privateKeyData32Bytes, requireNonZero: true)
            switch format {
            case .compressed:
                return try deriveCompressedPublicKey(fromPrivateKeyScalar: privateKeyScalar)
            case .uncompressed:
                break
            }
            let publicPoint = ScalarMultiplicationModel.mulG(privateKeyScalar)
            guard let publicAffine = publicPoint.convertToAffine() else {
                throw Error.invalidDerivedPublicKey
            }
            return encodePublicKey(publicAffine, format: format)
        }

        internal static func deriveCompressedPublicKey(
            fromPrivateKeyScalar privateKeyScalar: ScalarModel
        ) throws -> Data {
            try deriveParsedPublicKey(fromPrivateKeyScalar: privateKeyScalar)
                .compressedPublicKeyData
        }

        internal static func deriveParsedPublicKey(
            fromPrivateKeyScalar privateKeyScalar: ScalarModel
        ) throws -> ParsedPublicKeyModel {
            let publicPoint = ScalarMultiplicationModel.mulG(privateKeyScalar)
            guard let publicAffine = publicPoint.convertToAffine() else {
                throw Error.invalidDerivedPublicKey
            }
            return ParsedPublicKeyModel(affinePoint: publicAffine)
        }

        internal static func tweakAddPrivateKeyData32Bytes(
            _ privateKeyData32Bytes: Data,
            tweakData32Bytes: Data
        ) throws -> Data {
            let privateKeyScalar = try parsePrivateKeyScalar(privateKeyData32Bytes, requireNonZero: true)
            let tweakScalar = try parseTweakScalar(tweakData32Bytes, requireNonZero: false)
            return try tweakAddPrivateKey(
                privateKeyScalar,
                tweakScalar: tweakScalar
            ).data32Bytes
        }

        internal static func tweakAddPrivateKey(
            _ privateKeyScalar: ScalarModel,
            tweakScalar: ScalarModel
        ) throws -> ScalarModel {
            let derivedScalar = privateKeyScalar.addModN(tweakScalar)
            guard !derivedScalar.isZero else {
                throw Error.invalidDerivedPrivateKey
            }
            return derivedScalar
        }

        internal static func tweakAddPublicKey(
            _ publicKey: Data,
            tweakData32Bytes: Data,
            format: PublicKeyFormat? = nil
        ) throws -> Data {
            let parsedPublicKeyModel = try makeParsedPublicKey(publicKey: publicKey)
            let resolvedFormat = try resolveFormat(from: publicKey, format: format)
            return try tweakAddPublicKey(
                parsedPublicKeyModel,
                tweakData32Bytes: tweakData32Bytes,
                format: resolvedFormat
            )
        }

        internal static func tweakAddPublicKey(
            _ parsedPublicKeyModel: ParsedPublicKeyModel,
            tweakData32Bytes: Data,
            format: PublicKeyFormat
        ) throws -> Data {
            let tweakScalar = try parseTweakScalar(tweakData32Bytes, requireNonZero: false)
            let derivedParsedPublicKeyModel = try tweakAddParsedPublicKey(
                parsedPublicKeyModel,
                tweakScalar: tweakScalar
            )
            switch format {
            case .compressed:
                return derivedParsedPublicKeyModel.compressedPublicKeyData
            case .uncompressed:
                return derivedParsedPublicKeyModel.affinePoint.encodeUncompressed65()
            }
        }

        internal static func tweakAddPublicKey(
            _ verificationKeyModel: VerificationKeyModel,
            tweakData32Bytes: Data,
            format: PublicKeyFormat
        ) throws -> Data {
            try tweakAddPublicKey(
                verificationKeyModel.parsedPublicKeyModel,
                tweakData32Bytes: tweakData32Bytes,
                format: format
            )
        }
    }
}
