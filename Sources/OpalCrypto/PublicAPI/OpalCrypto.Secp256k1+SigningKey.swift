// OpalCrypto.Secp256k1+SigningKey.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Secp256k1 {
    /// An opaque secp256k1 signing capability.
    ///
    /// `SigningKey` is secret-bearing key material for signing and public-key derivation. It intentionally does not expose raw private-key bytes or serialization APIs.
    public struct SigningKey: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
        internal let parsedPrivateKeyModel: ParsedPrivateKeyModel

        /// Creates a signing capability from an existing private-key value.
        public init(privateKey: PrivateKey) {
            self.parsedPrivateKeyModel = ParsedPrivateKeyModel(
                validatedPrivateKeyScalar: privateKey.scalarModel
            )
        }

        /// Imports raw secp256k1 private-key bytes as an opaque signing capability.
        ///
        /// `rawRepresentation` is secret-bearing input. Prefer retaining `SigningKey` after import instead of repeatedly crossing raw byte boundaries.
        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("private_key_parse"),
                OpalDiagnostics.Field.algorithmField("secp256k1"),
                OpalDiagnostics.Field.formatField("raw"),
                OpalDiagnostics.Field.inputLengthField(rawRepresentation.count)
            ]
            do {
                self.parsedPrivateKeyModel = try ParsedPrivateKeyModel(
                    privateKeyData32Bytes: rawRepresentation
                )
            } catch let error as ParsedPrivateKeyModel.Error {
                let mappedError = Self.mapParsedPrivateKeyError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.privateKeyParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.privateKeyParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyParseSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(Self.privateKeyByteCount)
                ]
            )
        }

        /// The public key derived from this signing capability.
        public var publicKey: PublicKey {
            PublicKey(parsedPublicKeyModel: parsedPrivateKeyModel.parsedPublicKeyModel)
        }

        /// The verification key derived from this signing capability.
        public var verificationKey: OpalCrypto.Signature.VerificationKey {
            OpalCrypto.Signature.VerificationKey(
                verificationKeyModel: VerificationKeyModel(
                    parsedPublicKeyModel: parsedPrivateKeyModel.parsedPublicKeyModel
                )
            )
        }

        /// Hashes `message` once with SHA-256, then signs that digest with ECDSA.
        ///
        /// Prefer ``signECDSASHA256(message:format:noncePolicy:)`` in new code
        /// when the hashing contract should be explicit at the call site.
        public func signECDSA(
            message: Data,
            format: OpalCrypto.Signature.ECDSAFormat = .der,
            noncePolicy: OpalCrypto.Signature.ECDSANoncePolicy = .rfc6979
        ) throws -> OpalCrypto.Signature.ECDSA {
            try signECDSASHA256(
                message: message,
                format: format,
                noncePolicy: noncePolicy
            )
        }

        /// Hashes `message` once with SHA-256, then signs that digest with ECDSA.
        public func signECDSASHA256(
            message: Data,
            format: OpalCrypto.Signature.ECDSAFormat = .der,
            noncePolicy: OpalCrypto.Signature.ECDSANoncePolicy = .rfc6979
        ) throws -> OpalCrypto.Signature.ECDSA {
            try OpalCrypto.Signature.ECDSA.sign(
                digestData32Bytes: SecureHashAlgorithm256Model.hash(message),
                privateKeyScalar: parsedPrivateKeyModel.scalar,
                format: format,
                noncePolicy: noncePolicy,
                privateKeyByteCount: Self.privateKeyByteCount,
                payloadLengthField: OpalDiagnostics.Field.messageLengthField(message.count)
            )
        }

        /// Signs a 32-byte digest with deterministic ECDSA by default.
        public func signECDSA(
            digest: OpalCrypto.Signature.Digest,
            format: OpalCrypto.Signature.ECDSAFormat = .der,
            noncePolicy: OpalCrypto.Signature.ECDSANoncePolicy = .rfc6979
        ) throws -> OpalCrypto.Signature.ECDSA {
            try OpalCrypto.Signature.ECDSA.sign(
                digestData32Bytes: digest.rawRepresentation,
                privateKeyScalar: parsedPrivateKeyModel.scalar,
                format: format,
                noncePolicy: noncePolicy,
                privateKeyByteCount: Self.privateKeyByteCount,
                payloadLengthField: OpalDiagnostics.Field.publicField(
                    "digest_byte_count",
                    digest.rawRepresentation.count
                )
            )
        }

        /// Signs a 32-byte digest with Bitcoin Cash deterministic Schnorr signing by default.
        public func signSchnorr(
            digest: OpalCrypto.Signature.Digest,
            noncePolicy: OpalCrypto.Signature.SchnorrNoncePolicy = .bchDeterministic
        ) throws -> OpalCrypto.Signature.Schnorr {
            try OpalCrypto.Signature.Schnorr.sign(
                digest: digest,
                parsedPrivateKeyModel: parsedPrivateKeyModel,
                noncePolicy: noncePolicy
            )
        }

        /// A redacted description that never includes private-key bytes or parsed scalar state.
        public var description: String {
            "OpalCrypto.Secp256k1.SigningKey(redacted, curve: secp256k1, byteCount: \(Self.privateKeyByteCount))"
        }

        /// A redacted debug description that never includes private-key bytes or parsed scalar state.
        public var debugDescription: String {
            description
        }

        internal init(parsedPrivateKeyModel: ParsedPrivateKeyModel) {
            self.parsedPrivateKeyModel = parsedPrivateKeyModel
        }

        internal static let privateKeyByteCount = 32

        private static func mapParsedPrivateKeyError(
            _ error: ParsedPrivateKeyModel.Error
        ) -> OpalCrypto.Secp256k1.Error {
            switch error {
            case .invalidPrivateKeyLength(let actual):
                return .invalidPrivateKeyLength(expected: privateKeyByteCount, actual: actual)
            case .invalidPrivateKey:
                return .invalidPrivateKey
            }
        }
    }
}
