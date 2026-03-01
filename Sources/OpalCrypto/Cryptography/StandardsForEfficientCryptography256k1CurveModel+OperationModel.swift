// StandardsForEfficientCryptography256k1CurveModel+OperationModel.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel {
    public enum OperationModel {
        public enum PublicKeyFormat {
            case compressed
            case uncompressed
        }

        public enum Error: Swift.Error, Equatable {
            case invalidPrivateKeyLength(actual: Int)
            case invalidPrivateKeyValue
            case invalidPublicKeyLength(actual: Int)
            case invalidPublicKeyValue
            case invalidTweakLength(actual: Int)
            case invalidTweakValue
            case invalidDerivedPrivateKey
            case invalidDerivedPublicKey
        }

        public static var curveOrderN: Data {
            StandardsForEfficientCryptography256k1CurveModel.ConstantModel.n.data32Bytes
        }

        public static func validatePrivateKeyData32Bytes(_ privateKeyData32Bytes: Data) -> Bool {
            (try? ScalarModel(data32: privateKeyData32Bytes, requireNonZero: true)) != nil
        }

        public static func derivePublicKey(
            fromPrivateKeyData32Bytes privateKeyData32Bytes: Data,
            format: PublicKeyFormat = .compressed
        ) throws -> Data {
            let privateKeyScalar = try parsePrivateKeyScalar(privateKeyData32Bytes, requireNonZero: true)
            let publicPoint = ScalarMultiplicationModel.mulG(privateKeyScalar)
            guard let publicAffine = publicPoint.convertToAffine() else {
                throw Error.invalidDerivedPublicKey
            }
            return encodePublicKey(publicAffine, format: format)
        }

        public static func tweakAddPrivateKeyData32Bytes(
            _ privateKeyData32Bytes: Data,
            tweakData32Bytes: Data
        ) throws -> Data {
            let privateKeyScalar = try parsePrivateKeyScalar(privateKeyData32Bytes, requireNonZero: true)
            let tweakScalar = try parseTweakScalar(tweakData32Bytes, requireNonZero: false)
            let derivedScalar = privateKeyScalar.addModN(tweakScalar)
            guard !derivedScalar.isZero else {
                throw Error.invalidDerivedPrivateKey
            }
            return derivedScalar.data32Bytes
        }

        public static func tweakAddPublicKey(
            _ publicKey: Data,
            tweakData32Bytes: Data,
            format: PublicKeyFormat? = nil
        ) throws -> Data {
            let publicAffine = try parsePublicKeyAffine(publicKey)
            let tweakScalar = try parseTweakScalar(tweakData32Bytes, requireNonZero: true)
            let tweakPoint = ScalarMultiplicationModel.mulG(tweakScalar)
            let combined = JacobianPointModel(affine: publicAffine).add(tweakPoint)
            guard let derivedAffine = combined.convertToAffine() else {
                throw Error.invalidDerivedPublicKey
            }
            let resolvedFormat = try resolveFormat(from: publicKey, format: format)
            return encodePublicKey(derivedAffine, format: resolvedFormat)
        }
    }
}
