// OpalCrypto+Signature.swift

import Foundation

extension OpalCrypto {
    public enum Signature {
        public static func derivePublicKey(fromPrivateKey privateKey: Data) throws -> Data {
            try validatePrivateKeyLength(privateKey)
            do {
                return try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: privateKey)
            } catch {
                throw mapCryptographyError(error)
            }
        }

        public static func deriveVerificationKey(
            fromPrivateKey privateKey: Data
        ) throws -> VerificationKey {
            try validatePrivateKeyLength(privateKey)
            do {
                let verificationKeyModel = try StandardsForEfficientCryptography256k1CurveModel
                    .Operation.makeVerificationKey(
                        fromPrivateKeyData32Bytes: privateKey
                    )
                return VerificationKey(verificationKeyModel: verificationKeyModel)
            } catch {
                throw mapCryptographyError(error)
            }
        }

        public static func signECDSA(
            message: Data,
            privateKey: Data,
            format: ECDSAFormat,
            noncePolicy: ECDSANoncePolicy = .rfc6979
        ) throws -> Data {
            try validatePrivateKeyLength(privateKey)

            do {
                return try EllipticCurveDigitalSignatureAlgorithmModel.sign(
                    message: message,
                    with: privateKey,
                    in: format.internalFormat,
                    nonceFunction: noncePolicy.internalNoncePolicy
                )
            } catch {
                throw mapCryptographyError(error)
            }
        }

        /// Signs a caller-supplied 32-byte Schnorr digest.
        ///
        /// The caller is responsible for hashing the message before calling this API.
        public static func signSchnorr(
            digest: Data,
            privateKey: Data,
            noncePolicy: SchnorrNoncePolicy = .bip340Deterministic
        ) throws -> Data {
            try validatePrivateKeyLength(privateKey)
            try validateSchnorrDigestLength(digest)

            do {
                return try EllipticCurveDigitalSignatureAlgorithmModel.sign(
                    message: digest,
                    with: privateKey,
                    in: .schnorr,
                    nonceFunction: noncePolicy.internalNoncePolicy
                )
            } catch {
                throw mapCryptographyError(error)
            }
        }

        public static func verifyECDSA(
            signature: Data,
            message: Data,
            publicKey: Data,
            format: ECDSAFormat
        ) throws -> Bool {
            try validateSecp256k1PublicKey(publicKey)
            try validateECDSASignatureLength(signature, format: format)
            let verificationKey: VerificationKey
            do {
                verificationKey = try VerificationKey(publicKey: publicKey)
            } catch let error as VerificationKey.Error {
                throw mapVerificationKeyError(error)
            }

            return try verifyValidated(
                signature: signature,
                message: message,
                verificationKey: verificationKey,
                format: format.internalFormat
            )
        }

        public static func verifyECDSA(
            signature: Data,
            message: Data,
            verificationKey: VerificationKey,
            format: ECDSAFormat
        ) throws -> Bool {
            try validateECDSASignatureLength(signature, format: format)

            return try verifyValidated(
                signature: signature,
                message: message,
                verificationKey: verificationKey,
                format: format.internalFormat
            )
        }

        /// Verifies a Schnorr signature against a caller-supplied 32-byte digest.
        ///
        /// The caller is responsible for hashing the message before calling this API.
        public static func verifySchnorr(
            signature: Data,
            digest: Data,
            publicKey: Data
        ) throws -> Bool {
            try validateSecp256k1PublicKey(publicKey)
            try validateSchnorrSignatureLength(signature)
            try validateSchnorrDigestLength(digest)
            let verificationKey: VerificationKey
            do {
                verificationKey = try VerificationKey(publicKey: publicKey)
            } catch let error as VerificationKey.Error {
                throw mapVerificationKeyError(error)
            }

            return try verifyValidated(
                signature: signature,
                message: digest,
                verificationKey: verificationKey,
                format: .schnorr
            )
        }

        /// Verifies a Schnorr signature against a caller-supplied 32-byte digest.
        ///
        /// The caller is responsible for hashing the message before calling this API.
        public static func verifySchnorr(
            signature: Data,
            digest: Data,
            verificationKey: VerificationKey
        ) throws -> Bool {
            try validateSchnorrSignatureLength(signature)
            try validateSchnorrDigestLength(digest)

            return try verifyValidated(
                signature: signature,
                message: digest,
                verificationKey: verificationKey,
                format: .schnorr
            )
        }
    }
}
