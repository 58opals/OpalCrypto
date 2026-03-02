import Foundation

extension OpalCryptoFacade {
    public enum Signature {
        public enum Format: Sendable, Equatable {
            public enum EcdsaEncoding: Sendable, Equatable {
                case raw
                case der
            }

            case ecdsa(EcdsaEncoding)
            case schnorr
        }

        public enum NoncePolicy: Sendable, Equatable {
            case requestForComments6979
            case bitcoinImprovementProposalSchnorrDeterministic
            case systemRandom
        }

        public enum Error: Swift.Error, Equatable {
            case invalidPrivateKeyLength(expected: Int, actual: Int)
            case invalidPublicKeyLength(expected: Int, actual: Int)
            case invalidPublicKeyPrefix(actual: UInt8)
            case invalidDigestLength(expected: Int, actual: Int)
            case invalidSignatureLength(expected: Int, actual: Int)
            case cryptographyFailure
        }

        public static func derivePublicKey(fromPrivateKeyData privateKeyData: Data) throws -> Data {
            try validatePrivateKeyLength(privateKeyData)
            do {
                return try EllipticCurveDigitalSignatureAlgorithmModel.derivePublicKey(from: privateKeyData)
            } catch {
                throw mapCryptographyError(error)
            }
        }

        public static func sign(
            messageData: Data,
            privateKeyData: Data,
            format: Format,
            noncePolicy: NoncePolicy = .requestForComments6979
        ) throws -> Data {
            try validatePrivateKeyLength(privateKeyData)
            if case .schnorr = format {
                try validateSchnorrDigestLength(messageData)
            }

            do {
                return try EllipticCurveDigitalSignatureAlgorithmModel.sign(
                    message: messageData,
                    with: privateKeyData,
                    in: format.internalFormat,
                    nonceFunction: noncePolicy.internalNoncePolicy
                )
            } catch {
                throw mapCryptographyError(error)
            }
        }

        public static func verify(
            signatureData: Data,
            messageData: Data,
            publicKeyData: Data,
            format: Format
        ) throws -> Bool {
            try validateCompressedPublicKey(publicKeyData)
            try validateSignatureLength(signatureData, format: format)
            if case .schnorr = format {
                try validateSchnorrDigestLength(messageData)
            }

            do {
                return try EllipticCurveDigitalSignatureAlgorithmModel.verify(
                    signature: signatureData,
                    message: messageData,
                    publicKey: publicKeyData,
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

        private static func validateCompressedPublicKey(_ publicKeyData: Data) throws {
            guard publicKeyData.count == 33 else {
                throw Error.invalidPublicKeyLength(expected: 33, actual: publicKeyData.count)
            }
            guard let prefix = publicKeyData.first else {
                throw Error.invalidPublicKeyLength(expected: 33, actual: 0)
            }
            guard prefix == 0x02 || prefix == 0x03 else {
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

            return .cryptographyFailure
        }
    }
}
