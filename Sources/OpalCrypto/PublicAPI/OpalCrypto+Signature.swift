// OpalCrypto+Signature.swift

import Foundation

extension OpalCrypto {
    public enum Signature {
        public enum Format: Sendable, Equatable {
            public enum ECDSAEncoding: Sendable, Equatable {
                case raw
                case der
            }

            case ecdsa(ECDSAEncoding)
            case schnorr
        }

        public enum NoncePolicy: Sendable, Equatable {
            case rfc6979
            case bip340Deterministic
            case random
        }

        public enum Error: Swift.Error, Equatable {
            case invalidPrivateKeyLength(expected: Int, actual: Int)
            case invalidPublicKeyLength(expected: Int, actual: Int)
            case invalidPublicKeyPrefix(actual: UInt8)
            case invalidDigestLength(expected: Int, actual: Int)
            case invalidSignatureLength(expected: Int, actual: Int)
            case cryptographyFailure
        }

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

        public static func sign(
            message: Data,
            privateKey: Data,
            format: Format,
            nonce: NoncePolicy = .rfc6979
        ) throws -> Data {
            try validatePrivateKeyLength(privateKey)
            if case .schnorr = format {
                try validateSchnorrDigestLength(message)
            }

            do {
                return try EllipticCurveDigitalSignatureAlgorithmModel.sign(
                    message: message,
                    with: privateKey,
                    in: format.internalFormat,
                    nonceFunction: nonce.internalNoncePolicy
                )
            } catch {
                throw mapCryptographyError(error)
            }
        }

        public static func verify(
            signature: Data,
            message: Data,
            publicKey: Data,
            format: Format
        ) throws -> Bool {
            try validateSecp256k1PublicKey(publicKey)
            try validateSignatureLength(signature, format: format)
            if case .schnorr = format {
                try validateSchnorrDigestLength(message)
            }
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
                format: format
            )
        }

        public static func verify(
            signature: Data,
            message: Data,
            verificationKey: VerificationKey,
            format: Format
        ) throws -> Bool {
            try validateSignatureLength(signature, format: format)
            if case .schnorr = format {
                try validateSchnorrDigestLength(message)
            }

            return try verifyValidated(
                signature: signature,
                message: message,
                verificationKey: verificationKey,
                format: format
            )
        }

        private static func verifyValidated(
            signature: Data,
            message: Data,
            verificationKey: VerificationKey,
            format: Format
        ) throws -> Bool {
            do {
                return try EllipticCurveDigitalSignatureAlgorithmModel.verify(
                    signature: signature,
                    message: message,
                    verificationKeyModel: verificationKey.verificationKeyModel,
                    format: format.internalFormat
                )
            } catch {
                throw mapCryptographyError(error)
            }
        }

        private static func validatePrivateKeyLength(_ privateKeyData: Data) throws {
            guard privateKeyData.count == 32 else {
                throw Error.invalidPrivateKeyLength(expected: 32, actual: privateKeyData.count)
            }
        }

        private static func validateSecp256k1PublicKey(_ publicKeyData: Data) throws {
            guard publicKeyData.count == 33 || publicKeyData.count == 65 else {
                throw Error.invalidPublicKeyLength(expected: 33, actual: publicKeyData.count)
            }
            guard let prefix = publicKeyData.first else {
                throw Error.invalidPublicKeyLength(expected: 33, actual: 0)
            }
            let isValidPrefix = switch publicKeyData.count {
            case 33:
                prefix == 0x02 || prefix == 0x03
            case 65:
                prefix == 0x04
            default:
                false
            }
            guard isValidPrefix else {
                throw Error.invalidPublicKeyPrefix(actual: prefix)
            }
        }

        private static func validateSchnorrDigestLength(_ digestData: Data) throws {
            guard digestData.count == 32 else {
                throw Error.invalidDigestLength(expected: 32, actual: digestData.count)
            }
        }

        private static func validateSignatureLength(_ signatureData: Data, format: Format) throws {
            switch format {
            case .schnorr, .ecdsa(.raw):
                guard signatureData.count == 64 else {
                    throw Error.invalidSignatureLength(expected: 64, actual: signatureData.count)
                }
            case .ecdsa(.der):
                break
            }
        }

        private static func mapCryptographyError(_ error: Swift.Error) -> Error {
            if let signatureError = error as? EllipticCurveDigitalSignatureAlgorithmModel.Error {
                switch signatureError {
                case .invalidCompressedPublicKeyLength:
                    return .invalidPublicKeyLength(expected: 33, actual: 0)
                case .invalidCompressedPublicKeyPrefix:
                    return .invalidPublicKeyPrefix(actual: 0)
                case .invalidDigestLength(let expected, let actual):
                    return .invalidDigestLength(expected: expected, actual: actual)
                case .invalidHashIterationCount:
                    return .cryptographyFailure
                }
            }

            if let schnorrError = error as? SchnorrSignatureModel.Error {
                switch schnorrError {
                case .invalidDigestLength(let actual):
                    return .invalidDigestLength(expected: 32, actual: actual)
                case .invalidPrivateKeyLength(let actual):
                    return .invalidPrivateKeyLength(expected: 32, actual: actual)
                case .invalidPublicKeyLength(let actual):
                    return .invalidPublicKeyLength(expected: 33, actual: actual)
                case .invalidSignatureLength(let actual):
                    return .invalidSignatureLength(expected: 64, actual: actual)
                case .invalidPrivateKeyValue, .randomGenerationFailed:
                    return .cryptographyFailure
                }
            }

            if let secpError = error as? StandardsForEfficientCryptography256k1CurveModel.Error {
                switch secpError {
                case .invalidDigestLength(let actual):
                    return .invalidDigestLength(expected: 32, actual: actual)
                case .invalidPrivateKeyLength(let actual):
                    return .invalidPrivateKeyLength(expected: 32, actual: actual)
                case .invalidPublicKeyLength(let actual):
                    return .invalidPublicKeyLength(expected: 33, actual: actual)
                case .invalidSignatureLength(let actual):
                    return .invalidSignatureLength(expected: 64, actual: actual)
                case .invalidPrivateKeyValue,
                     .invalidSignatureScalar,
                     .signatureComponentZero,
                     .derMalformed,
                     .derNonCanonical,
                     .randomGenerationFailed:
                    return .cryptographyFailure
                }
            }

            if let secpFacadeError = error as? OpalCrypto.Secp256k1.Error {
                switch secpFacadeError {
                case .invalidPrivateKeyLength(let expected, let actual):
                    return .invalidPrivateKeyLength(expected: expected, actual: actual)
                case .invalidPrivateKey, .invalidDerivedKey:
                    return .cryptographyFailure
                case .invalidPublicKeyLength(let expected, let actual):
                    return .invalidPublicKeyLength(expected: expected, actual: actual)
                case .invalidPublicKeyPrefix(let actual):
                    return .invalidPublicKeyPrefix(actual: actual)
                case .invalidPublicKey,
                     .invalidTweakLength,
                     .invalidTweak,
                     .invalidSignatureLength,
                     .invalidSignature,
                     .invalidDER,
                     .nonCanonicalDER,
                     .randomGenerationFailed:
                    return .cryptographyFailure
                }
            }

            return .cryptographyFailure
        }

        private static func mapVerificationKeyError(
            _ error: VerificationKey.Error
        ) -> Error {
            switch error {
            case .invalidPublicKeyLength(let actual):
                return .invalidPublicKeyLength(expected: 33, actual: actual)
            case .invalidPublicKeyPrefix(let actual):
                return .invalidPublicKeyPrefix(actual: actual)
            case .invalidPublicKey:
                return .cryptographyFailure
            }
        }
    }
}
