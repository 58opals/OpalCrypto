// OpalCrypto.Communication+SymmetricKey.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Communication {
    /// A symmetric key for OpalCrypto communication helpers.
    ///
    /// `SymmetricKey` is secret-bearing encryption material. Keep raw bytes behind explicit encryption/decryption boundaries and never log them.
    public struct SymmetricKey: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
        /// The raw 32-byte symmetric key.
        ///
        /// This value is secret-bearing and must not be logged or included in diagnostics.
        public let rawRepresentation: Data

        /// Creates a symmetric key from raw bytes.
        ///
        /// Diagnostics record only public-safe metadata such as key byte count and error code.
        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("symmetric_key_parse"),
                OpalDiagnostics.Field.publicField("symmetric_key_byte_count", rawRepresentation.count),
                OpalDiagnostics.Field.inputLengthField(rawRepresentation.count)
            ]
            guard rawRepresentation.count == 32 else {
                let error = Error.invalidSymmetricKeyLength(expected: 32, actual: rawRepresentation.count)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                    event: OpalDiagnostics.Event.communicationSymmetricKeyParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationSymmetricKeyParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
            self.rawRepresentation = Data(rawRepresentation)
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                event: OpalDiagnostics.Event.communicationSymmetricKeyParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationSymmetricKeyParseSucceeded),
                fields: fields
            )
        }

        /// A redacted description that never includes symmetric-key bytes.
        public var description: String {
            "OpalCrypto.Communication.SymmetricKey(redacted, byteCount: \(rawRepresentation.count))"
        }

        /// A redacted debug description that never includes symmetric-key bytes.
        public var debugDescription: String {
            description
        }

        internal init(validatedRawRepresentation: Data) {
            self.rawRepresentation = Data(validatedRawRepresentation)
        }
    }
}
