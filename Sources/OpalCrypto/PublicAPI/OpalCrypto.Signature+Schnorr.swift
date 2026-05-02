// OpalCrypto.Signature+Schnorr.swift

import Foundation

extension OpalCrypto.Signature {
    public struct Schnorr: Sendable, Equatable {
        internal let signatureModel: SchnorrSignatureModel.Signature

        public var rawRepresentation: Data {
            signatureModel.raw64ByteSignatureData
        }

        public init(rawRepresentation: Data) throws {
            do {
                signatureModel = try SchnorrSignatureModel.Signature(
                    raw64ByteSignatureData: rawRepresentation
                )
                _ = try FieldElementModel(data32: signatureModel.r)
                _ = try ScalarModel(data32: signatureModel.s, requireNonZero: false)
            } catch SchnorrSignatureModel.Error.invalidSignatureLength(let actual) {
                throw Error.invalidSignatureLength(expected: 64, actual: actual)
            } catch {
                throw Error.invalidSignature
            }
        }

        internal init(signatureModel: SchnorrSignatureModel.Signature) {
            self.signatureModel = signatureModel
        }

        public static func sign(
            digest: Digest,
            privateKey: OpalCrypto.Secp256k1.PrivateKey,
            noncePolicy: SchnorrNoncePolicy = .bip340Deterministic
        ) throws -> Schnorr {
            do {
                let signatureData = try EllipticCurveDigitalSignatureAlgorithmModel.sign(
                    message: digest.rawRepresentation,
                    with: privateKey.rawRepresentation,
                    in: .schnorr,
                    nonceFunction: noncePolicy.internalNoncePolicy
                )
                return try Schnorr(rawRepresentation: signatureData)
            } catch {
                throw OpalCrypto.Signature.mapCryptographyError(error)
            }
        }

        public func verify(
            digest: Digest,
            publicKey: OpalCrypto.Secp256k1.PublicKey
        ) throws -> Bool {
            try verify(
                digest: digest,
                verificationKey: VerificationKey(publicKey: publicKey)
            )
        }

        public func verify(
            digest: Digest,
            verificationKey: VerificationKey
        ) throws -> Bool {
            try OpalCrypto.Signature.verifyValidated(
                signature: rawRepresentation,
                message: digest.rawRepresentation,
                verificationKey: verificationKey,
                format: .schnorr
            )
        }
    }
}
