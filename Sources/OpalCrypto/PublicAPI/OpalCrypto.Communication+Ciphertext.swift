// OpalCrypto.Communication+Ciphertext.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Communication {
    public struct Ciphertext: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("ciphertext_parse"),
                OpalDiagnostics.Field.ciphertextLengthField(rawRepresentation.count)
            ]
            do {
                try CommunicationBoxModel.validateCiphertextEnvelope(rawRepresentation)
            } catch {
                let mappedError = Error.invalidCiphertext
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                    event: OpalDiagnostics.Event.communicationCiphertextParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationCiphertextParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
            self.rawRepresentation = Data(rawRepresentation)
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.communication).record(
                event: OpalDiagnostics.Event.communicationCiphertextParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.communicationCiphertextParseSucceeded),
                fields: fields
            )
        }

        internal init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
