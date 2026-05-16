// OpalCrypto.Communication+Ciphertext.swift

import Foundation

extension OpalCrypto.Communication {
    public struct Ciphertext: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalCryptoDiagnostics.operationField("ciphertext_parse"),
                OpalCryptoDiagnostics.ciphertextLengthField(rawRepresentation.count)
            ]
            do {
                try CommunicationBoxModel.validateCiphertextEnvelope(rawRepresentation)
            } catch {
                let mappedError = Error.invalidCiphertext
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.communicationCiphertextParseFailed,
                    category: OpalCryptoDiagnostics.Category.communication,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
            self.rawRepresentation = Data(rawRepresentation)
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.communicationCiphertextParseSucceeded,
                category: OpalCryptoDiagnostics.Category.communication,
                fields: fields
            )
        }

        internal init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = Data(rawRepresentation)
        }
    }
}
