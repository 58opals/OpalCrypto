// OpalCryptoBoundaryModel.swift

import Foundation

public enum OpalCryptoBoundaryModel {
    public enum SignatureModel {
        public static func derivePublicKey(fromPrivateKeyData privateKeyData: Data) throws -> Data {
            try EllipticCurveDigitalSignatureAlgorithmModel.derivePublicKey(from: privateKeyData)
        }

        public static func sign(
            messageData: Data,
            privateKeyData: Data,
            format: EllipticCurveDigitalSignatureAlgorithmModel.SignatureFormatModel,
            nonceGenerationPolicy: NonceGenerationPolicy = .requestForComments6979BitcoinCashDefault
        ) throws -> Data {
            try EllipticCurveDigitalSignatureAlgorithmModel.sign(
                message: messageData,
                with: privateKeyData,
                in: format,
                nonceFunction: nonceGenerationPolicy
            )
        }

        public static func verify(
            signatureData: Data,
            messageData: Data,
            publicKeyData: Data,
            format: EllipticCurveDigitalSignatureAlgorithmModel.SignatureFormatModel
        ) throws -> Bool {
            try EllipticCurveDigitalSignatureAlgorithmModel.verify(
                signature: signatureData,
                message: messageData,
                publicKey: publicKeyData,
                format: format
            )
        }
    }

    public enum HashingModel {
        public static func makeSecureHashAlgorithm256(_ data: Data) -> Data {
            SecureHashAlgorithm256Model.hash(data)
        }

        public static func makeSecureHash256(_ data: Data) -> Data {
            SecureHash256Model.hash(data)
        }

        public static func makeSecureHash160(_ data: Data) -> Data {
            SecureHash160Model.hash(data)
        }

        public static func makeHashBasedMessageAuthenticationCodeSecureHashAlgorithm512(data: Data, key: Data) -> Data {
            HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.hash(data, key: key)
        }
    }

    public enum EncodingModel {
        public static func encodeBase58(_ data: Data) -> String {
            Base58EncodingModel.encode(data)
        }

        public static func decodeBase58(_ text: String) -> Data? {
            Base58EncodingModel.decode(text)
        }

        public static func encodeBase32(_ data: Data, interpretedAsFiveBitValues: Bool) -> String {
            Base32EncodingModel.encode(data, interpretedAsFiveBitValues: interpretedAsFiveBitValues)
        }

        public static func decodeBase32(_ text: String, interpretedAsFiveBitValues: Bool) throws -> Data {
            try Base32EncodingModel.decode(text, interpretedAsFiveBitValues: interpretedAsFiveBitValues)
        }

        public static func computePolynomialModuloChecksum(_ values: [UInt8]) -> UInt64 {
            PolynomialModuloChecksumModel.compute(values)
        }
    }

    public enum KeyDerivationModel {
        public static func derivePasswordBasedKeyDerivationFunction2Key(
            passwordData: Data,
            saltData: Data,
            iterationCount: Int,
            derivedKeyLength: Int?
        ) throws -> Data {
            try PasswordBasedKeyDerivationFunction2Model(
                password: passwordData,
                salt: saltData,
                iterationCount: iterationCount,
                derivedKeyLength: derivedKeyLength
            ).deriveKey()
        }
    }

    public enum NumericModel {
        public typealias LargeUnsignedInteger = LargeUnsignedIntegerArithmeticModel
        public typealias Unsigned256BitInteger = Unsigned256BitIntegerModel
        public typealias Unsigned512BitInteger = Unsigned512BitIntegerModel
    }
}
