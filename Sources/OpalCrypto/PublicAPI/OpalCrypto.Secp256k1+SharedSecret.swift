// OpalCrypto.Secp256k1+SharedSecret.swift

import Foundation

extension OpalCrypto.Secp256k1 {
    public struct SharedSecret: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalCryptoDiagnostics.operationField("shared_secret_parse"),
                OpalCryptoDiagnostics.inputLengthField(rawRepresentation.count)
            ]
            guard rawRepresentation.count == 32 else {
                let error = Error.invalidDerivedKey
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.sharedSecretParseFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
            self.rawRepresentation = Data(rawRepresentation)
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.sharedSecretParseSucceeded,
                category: OpalCryptoDiagnostics.Category.key,
                fields: fields + [
                    OpalCryptoDiagnostics.outputLengthField(self.rawRepresentation.count)
                ]
            )
        }

        internal init(validatedRawRepresentation: Data) {
            self.rawRepresentation = Data(validatedRawRepresentation)
        }
    }
}
