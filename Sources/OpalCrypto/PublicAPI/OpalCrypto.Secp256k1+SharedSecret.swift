// OpalCrypto.Secp256k1+SharedSecret.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Secp256k1 {
    public struct SharedSecret: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("shared_secret_parse"),
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

        internal init(validatedRawRepresentation: Data) {
            self.rawRepresentation = Data(validatedRawRepresentation)
        }
    }
}
