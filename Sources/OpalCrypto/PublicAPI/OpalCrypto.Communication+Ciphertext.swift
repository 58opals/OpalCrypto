// OpalCrypto.Communication+Ciphertext.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Communication {
    /// An authenticated communication ciphertext envelope.
    public struct Ciphertext: Sendable, Equatable {
        /// The complete serialized ciphertext envelope.
        public let rawRepresentation: Data

        /// Validates and imports a serialized ciphertext envelope.
        ///
        /// - Throws: ``OpalCrypto/Communication/Error/invalidCiphertext`` when the envelope is shorter than the authenticated format requires.
        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("ciphertext_parse"),
                OpalDiagnostics.Field.ciphertextLengthField(rawRepresentation.count),
                OpalDiagnostics.Field.publicField(
                    "minimum_ciphertext_byte_count",
                    CommunicationBoxModel.minimumCiphertextLength
                )
            ]
            do {
                try CommunicationBoxModel.validateCiphertextEnvelope(rawRepresentation)
            } catch {
                let mappedError = Error.invalidCiphertext
                Self.recordParseFailed(mappedError, fields: fields)
                throw mappedError
            }
            self.rawRepresentation = Data(rawRepresentation)
            Self.recordParseSucceeded(fields: fields)
        }

        private static func recordParseSucceeded(fields: [OpalDiagnostics.Field]) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                event: OpalDiagnostics.Event.communicationCiphertextParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationCiphertextParseSucceeded),
                fields: fields
            )
        }

        private static func recordParseFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                event: OpalDiagnostics.Event.communicationCiphertextParseFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationCiphertextParseFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }

        internal init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
