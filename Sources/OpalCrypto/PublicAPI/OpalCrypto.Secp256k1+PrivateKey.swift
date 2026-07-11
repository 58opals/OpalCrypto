// OpalCrypto.Secp256k1+PrivateKey.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Secp256k1 {
    /// A secp256k1 private key.
    ///
    /// `PrivateKey` is secret-bearing key material. Its raw representation can sign messages, derive public keys, and derive shared secrets, so keep it behind explicit secret-access or signing/authoring boundaries.
    public struct PrivateKey: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
        internal let scalarModel: ScalarModel

        /// The raw 32-byte private key.
        ///
        /// This value is secret-bearing and must not be logged or included in diagnostics.
        public let rawRepresentation: Data

        /// Creates a private key from raw secp256k1 key bytes.
        ///
        /// Diagnostics record only public-safe metadata such as byte count, curve name, and error code.
        public init(rawRepresentation: Data) throws {
            let normalizedRawRepresentation = Data(rawRepresentation)
            let fields = [
                OpalDiagnostics.Field.operationField("private_key_parse"),
                OpalDiagnostics.Field.algorithmField("secp256k1"),
                OpalDiagnostics.Field.formatField("raw"),
                OpalDiagnostics.Field.inputLengthField(rawRepresentation.count)
            ]
            do {
                self.scalarModel = try StandardsForEfficientCryptography256k1CurveModel.Operation
                    .parsePrivateKeyScalar(
                        normalizedRawRepresentation,
                        requireNonZero: true
                    )
            } catch let operationError as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                let error = OpalCrypto.Secp256k1.mapOperationError(operationError)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.privateKeyParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
            self.rawRepresentation = normalizedRawRepresentation
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.privateKeyParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyParseSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(self.rawRepresentation.count)
                ]
            )
        }

        /// A redacted description that never includes private key bytes.
        public var description: String {
            "OpalCrypto.Secp256k1.PrivateKey(redacted, curve: secp256k1, byteCount: \(rawRepresentation.count))"
        }

        /// A redacted debug description that never includes private key bytes.
        public var debugDescription: String {
            description
        }

        internal init(validatedRawRepresentation: Data) {
            let normalizedRawRepresentation = Data(validatedRawRepresentation)
            guard let scalarModel = try? StandardsForEfficientCryptography256k1CurveModel.Operation
                .parsePrivateKeyScalar(
                    normalizedRawRepresentation,
                    requireNonZero: true
                ) else {
                preconditionFailure("A validated private-key representation must contain a nonzero scalar.")
            }
            self.rawRepresentation = normalizedRawRepresentation
            self.scalarModel = scalarModel
        }

        internal init(validatedScalarModel: ScalarModel) {
            precondition(!validatedScalarModel.isZero)
            self.rawRepresentation = validatedScalarModel.data32Bytes
            self.scalarModel = validatedScalarModel
        }

        /// Creates an opaque signing capability from this private key.
        ///
        /// Prefer retaining the returned `SigningKey` for signing workflows instead of repeatedly reading raw private-key bytes.
        public func makeSigningKey() -> SigningKey {
            SigningKey(privateKey: self)
        }

        /// Generates a new secp256k1 private key with secure randomness.
        ///
        /// The returned key is secret-bearing. Diagnostics record only public-safe metadata such as curve name and output byte count.
        public static func generate() throws -> PrivateKey {
            let fields = [
                OpalDiagnostics.Field.operationField("private_key_generate"),
                OpalDiagnostics.Field.algorithmField("secp256k1"),
                OpalDiagnostics.Field.formatField("raw")
            ]
            do {
                let privateKeyData = try StandardsForEfficientCryptography256k1CurveModel.Operation
                    .generatePrivateKeyData32Bytes()
                let privateKey = PrivateKey(validatedRawRepresentation: privateKeyData)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.privateKeyGenerateSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyGenerateSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.outputLengthField(privateKey.rawRepresentation.count)
                    ]
                )
                return privateKey
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                let mappedError = OpalCrypto.Secp256k1.mapOperationError(error)
                recordGenerateFailed(mappedError, fields: fields)
                throw mappedError
            } catch let error as Error {
                recordGenerateFailed(error, fields: fields)
                throw error
            }
        }

        private static func recordGenerateFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.privateKeyGenerateFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyGenerateFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }
    }
}
