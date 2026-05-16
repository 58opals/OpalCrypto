// OpalCrypto.Communication+SymmetricKey.swift

import Foundation

extension OpalCrypto.Communication {
    public struct SymmetricKey: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalCryptoDiagnostics.operationField("symmetric_key_parse"),
                OpalCryptoDiagnostics.inputLengthField(rawRepresentation.count)
            ]
            guard rawRepresentation.count == 32 else {
                let error = Error.invalidSymmetricKeyLength(expected: 32, actual: rawRepresentation.count)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.communicationSymmetricKeyParseFailed,
                    category: OpalCryptoDiagnostics.Category.communication,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
            self.rawRepresentation = Data(rawRepresentation)
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.communicationSymmetricKeyParseSucceeded,
                category: OpalCryptoDiagnostics.Category.communication,
                fields: fields
            )
        }

        internal init(validatedRawRepresentation: Data) {
            self.rawRepresentation = Data(validatedRawRepresentation)
        }
    }
}
