// OpalCryptoBoundaryModel.swift

import Foundation

public enum OpalCryptoBoundaryModel {
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

    public enum Hashing {
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

    public enum Encoding {
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

    public enum KeyDerivation {
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

    public enum Numeric {
        public struct UInt256: Sendable, Equatable {
            internal let rawValue: Unsigned256BitIntegerModel

            public init(data32Bytes: Data) throws {
                do {
                    self.rawValue = try Unsigned256BitIntegerModel(data32Bytes: data32Bytes)
                } catch {
                    throw Error.invalidDataLength(expected: 32, actual: data32Bytes.count)
                }
            }

            public var data32Bytes: Data {
                rawValue.data32Bytes
            }

            public var isZero: Bool {
                rawValue.isZero
            }

            public var isOne: Bool {
                rawValue.isOne
            }

            public var isLeastSignificantBitSet: Bool {
                rawValue.isLeastSignificantBitSet
            }

            public var mostSignificantBitIndex: Int? {
                rawValue.mostSignificantBitIndex
            }

            public func testBit(at index: Int) -> Bool {
                rawValue.testBit(at: index)
            }

            public func compare(to other: UInt256) -> ComparisonResult {
                rawValue.compare(to: other.rawValue)
            }

            public func add(_ other: UInt256) -> (sum: UInt256, carry: Bool) {
                let result = rawValue.add(other.rawValue)
                return (UInt256(rawValue: result.sum), result.carry)
            }

            public func subtract(_ other: UInt256) -> (difference: UInt256, borrow: Bool) {
                let result = rawValue.subtract(other.rawValue)
                return (UInt256(rawValue: result.difference), result.borrow)
            }

            public func multiplyFullWidth(by other: UInt256) -> UInt512 {
                UInt512(rawValue: rawValue.multiplyFullWidth(by: other.rawValue))
            }

            public func squareFullWidth() -> UInt512 {
                UInt512(rawValue: rawValue.squareFullWidth())
            }

            public func shiftRightOneBit() -> UInt256 {
                UInt256(rawValue: rawValue.shiftRightOneBit())
            }

            public mutating func shiftRightOneBitInPlace() {
                var value = rawValue
                value.shiftRightOneBitInPlace()
                self = UInt256(rawValue: value)
            }

            public func subtractWord(_ value: UInt64) -> UInt256 {
                UInt256(rawValue: rawValue.subtractWord(value))
            }

            public mutating func subtractWordInPlace(_ value: UInt64) {
                var number = rawValue
                number.subtractWordInPlace(value)
                self = UInt256(rawValue: number)
            }

            public func addWord(_ value: UInt64) -> UInt256 {
                UInt256(rawValue: rawValue.addWord(value))
            }

            public mutating func addWordInPlace(_ value: UInt64) {
                var number = rawValue
                number.addWordInPlace(value)
                self = UInt256(rawValue: number)
            }

            internal init(rawValue: Unsigned256BitIntegerModel) {
                self.rawValue = rawValue
            }
        }

        public struct UInt512: Sendable, Equatable {
            internal let rawValue: Unsigned512BitIntegerModel

            public init(data64Bytes: Data) throws {
                do {
                    self.rawValue = try Unsigned512BitIntegerModel(data64Bytes: data64Bytes)
                } catch {
                    throw Error.invalidDataLength(expected: 64, actual: data64Bytes.count)
                }
            }

            public var data64Bytes: Data {
                rawValue.data64Bytes
            }

            public var isZero: Bool {
                rawValue.isZero
            }

            internal init(rawValue: Unsigned512BitIntegerModel) {
                self.rawValue = rawValue
            }
        }

        public struct BigUnsignedInteger: Comparable, Sendable {
            internal var rawValue: LargeUnsignedIntegerArithmeticModel

            public static let zero = BigUnsignedInteger(rawValue: .zero)

            public init(_ value: UInt64) {
                self.rawValue = LargeUnsignedIntegerArithmeticModel(value)
            }

            public init(_ data: Data) {
                self.rawValue = LargeUnsignedIntegerArithmeticModel(data)
            }

            public var isZero: Bool {
                rawValue.isZero
            }

            public func serialize() -> Data {
                rawValue.serialize()
            }

            public func shiftLeft(by bits: Int) -> BigUnsignedInteger {
                BigUnsignedInteger(rawValue: rawValue.shiftLeft(by: bits))
            }

            public func shiftRight(by bits: Int) -> BigUnsignedInteger {
                BigUnsignedInteger(rawValue: rawValue.shiftRight(by: bits))
            }

            public mutating func add(_ addend: Int) {
                rawValue.add(addend)
            }

            public mutating func multiply(by multiplier: Int) {
                rawValue.multiply(by: multiplier)
            }

            public mutating func divide(by divisor: Int) -> Int {
                rawValue.divide(by: divisor)
            }

            public static func < (lhs: BigUnsignedInteger, rhs: BigUnsignedInteger) -> Bool {
                lhs.rawValue < rhs.rawValue
            }

            internal init(rawValue: LargeUnsignedIntegerArithmeticModel) {
                self.rawValue = rawValue
            }
        }

        public enum Error: Swift.Error, Equatable {
            case invalidDataLength(expected: Int, actual: Int)
        }
    }
}

private extension OpalCryptoBoundaryModel.Signature.Format {
    var internalFormat: EllipticCurveDigitalSignatureAlgorithmModel.SignatureFormatModel {
        switch self {
        case .ecdsa(let encoding):
            switch encoding {
            case .raw:
                return .ecdsa(.raw)
            case .der:
                return .ecdsa(.distinguishedEncodingRules)
            }
        case .schnorr:
            return .schnorr
        }
    }
}

private extension OpalCryptoBoundaryModel.Signature.NoncePolicy {
    var internalNoncePolicy: NonceGenerationPolicy {
        switch self {
        case .requestForComments6979:
            return .requestForComments6979BitcoinCashDefault
        case .bitcoinImprovementProposalSchnorrDeterministic:
            return .bitcoinImprovementProposalSchnorrDeterministic
        case .systemRandom:
            return .systemRandom
        }
    }
}
