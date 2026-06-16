// OpalCrypto.Secp256k1+SharedSecret.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Secp256k1 {
    /// A raw secp256k1 ECDH shared secret.
    ///
    /// `SharedSecret` is secret-bearing key agreement material. Use it only as input to cryptographic derivation or encryption boundaries, and never log the raw bytes.
    public struct SharedSecret: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
        /// The raw 32-byte shared secret.
        ///
        /// This value is secret-bearing and must not be logged or included in diagnostics.
        public let rawRepresentation: Data

        /// Creates a shared secret from raw bytes.
        ///
        /// Diagnostics record only public-safe metadata such as byte count, curve name, and error code.
        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("shared_secret_parse"),
                OpalDiagnostics.Field.algorithmField("secp256k1"),
                OpalDiagnostics.Field.inputLengthField(rawRepresentation.count)
            ]
            guard rawRepresentation.count == 32 else {
                let error = Error.invalidDerivedKey
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.sharedSecretParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.sharedSecretParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
            self.rawRepresentation = Data(rawRepresentation)
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.sharedSecretParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.sharedSecretParseSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(self.rawRepresentation.count)
                ]
            )
        }

        /// A redacted description that never includes shared-secret bytes.
        public var description: String {
            "OpalCrypto.Secp256k1.SharedSecret(redacted, curve: secp256k1, byteCount: \(rawRepresentation.count))"
        }

        /// A redacted debug description that never includes shared-secret bytes.
        public var debugDescription: String {
            description
        }

        internal init(validatedRawRepresentation: Data) {
            self.rawRepresentation = Data(validatedRawRepresentation)
        }
    }
}
