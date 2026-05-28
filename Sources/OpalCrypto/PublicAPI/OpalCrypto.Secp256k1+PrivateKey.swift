// OpalCrypto.Secp256k1+PrivateKey.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Secp256k1 {
    public struct PrivateKey: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("private_key_parse"),
                OpalDiagnostics.Field.formatField("raw"),
                OpalDiagnostics.Field.inputLengthField(rawRepresentation.count)
            ]
            do {
                try OpalCrypto.Secp256k1.validatePrivateKey(rawRepresentation)
            } catch let error as Error {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.privateKeyParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(error)
                )
                throw error
            }
            self.rawRepresentation = Data(rawRepresentation)
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.privateKeyParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyParseSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(self.rawRepresentation.count)
                ]
            )
        }

        internal init(validatedRawRepresentation: Data) {
            self.rawRepresentation = Data(validatedRawRepresentation)
        }

        public static func generate() throws -> PrivateKey {
            let fields = [
                OpalDiagnostics.Field.operationField("private_key_generate"),
                OpalDiagnostics.Field.algorithmField("secp256k1"),
                OpalDiagnostics.Field.formatField("raw")
            ]
            do {
                let privateKeyData = try StandardsForEfficientCryptography256k1CurveModel.Operation
                    .generatePrivateKeyData32Bytes()
                let privateKey = PrivateKey(validatedRawRepresentation: privateKeyData)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.privateKeyGenerateSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyGenerateSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.outputLengthField(privateKey.rawRepresentation.count)
                    ]
                )
                return privateKey
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                let mappedError = OpalCrypto.Secp256k1.mapOperationError(error)
                recordGenerateFailed(mappedError, fields: fields)
                throw mappedError
            } catch let error as Error {
                recordGenerateFailed(error, fields: fields)
                throw error
            }
        }

        private static func recordGenerateFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.privateKeyGenerateFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.privateKeyGenerateFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }
    }
}
