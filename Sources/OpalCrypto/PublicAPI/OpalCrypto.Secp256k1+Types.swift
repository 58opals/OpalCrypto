// OpalCrypto.Secp256k1+Types.swift

import Foundation

extension OpalCrypto.Secp256k1 {
    public struct PrivateKey: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            try OpalCrypto.Secp256k1.validatePrivateKey(rawRepresentation)
            self.rawRepresentation = rawRepresentation
        }

        public static func generate() throws -> PrivateKey {
            do {
                return try PrivateKey(
                    rawRepresentation: StandardsForEfficientCryptography256k1CurveModel.Operation
                        .generatePrivateKeyData32Bytes()
                )
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                throw OpalCrypto.Secp256k1.mapOperationError(error)
            }
        }
    }

    public struct PublicKey: Sendable, Equatable {
        internal let parsedPublicKeyModel: ParsedPublicKeyModel

        public var rawRepresentation: Data {
            parsedPublicKeyModel.compressedPublicKeyData
        }

        public var compressedRepresentation: Data {
            parsedPublicKeyModel.compressedPublicKeyData
        }

        public var uncompressedRepresentation: Data {
            parsedPublicKeyModel.affinePoint.encodeUncompressed65()
        }

        public init(rawRepresentation: Data) throws {
            do {
                parsedPublicKeyModel = try ParsedPublicKeyModel(publicKeyData: rawRepresentation)
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyLength(let actual) {
                throw Error.invalidPublicKeyLength(
                    expected: expectedSecp256k1PublicKeyLength(for: rawRepresentation),
                    actual: actual
                )
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyPrefix(let actual) {
                throw Error.invalidPublicKeyPrefix(actual: actual)
            } catch {
                throw Error.invalidPublicKey
            }
        }

        internal init(parsedPublicKeyModel: ParsedPublicKeyModel) {
            self.parsedPublicKeyModel = parsedPublicKeyModel
        }

        internal init(verificationKeyModel: VerificationKeyModel) {
            self.parsedPublicKeyModel = verificationKeyModel.parsedPublicKeyModel
        }
    }

    public struct Scalar: Sendable, Equatable {
        internal let scalarModel: ScalarModel

        public var rawRepresentation: Data {
            scalarModel.data32Bytes
        }

        public init(rawRepresentation: Data) throws {
            do {
                scalarModel = try ScalarModel(data32: rawRepresentation, requireNonZero: false)
            } catch ScalarModel.Error.invalidDataLength(let expected, let actual) {
                precondition(expected == 32)
                throw Error.invalidTweakLength(expected: expected, actual: actual)
            } catch {
                throw Error.invalidTweak
            }
        }

        internal init(scalarModel: ScalarModel) {
            self.scalarModel = scalarModel
        }
    }

    public struct SharedSecret: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 32 else {
                throw Error.invalidDerivedKey
            }
            self.rawRepresentation = rawRepresentation
        }
    }
}
