// OpalCrypto.Communication+SymmetricKey.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Communication {
    public struct SymmetricKey: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("symmetric_key_parse"),
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

        internal init(validatedRawRepresentation: Data) {
            self.rawRepresentation = Data(validatedRawRepresentation)
        }
    }
}
