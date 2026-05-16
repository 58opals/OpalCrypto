// OpalCrypto.Secp256k1+PrivateKey.swift

import Foundation

extension OpalCrypto.Secp256k1 {
    public struct PrivateKey: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalCryptoDiagnostics.operationField("private_key_parse"),
                OpalCryptoDiagnostics.formatField("raw"),
                OpalCryptoDiagnostics.inputLengthField(rawRepresentation.count)
            ]
            do {
                try OpalCrypto.Secp256k1.validatePrivateKey(rawRepresentation)
            } catch let error as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.privateKeyParseFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
            self.rawRepresentation = Data(rawRepresentation)
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.privateKeyParseSucceeded,
                category: OpalCryptoDiagnostics.Category.key,
                fields: fields + [
                    OpalCryptoDiagnostics.outputLengthField(self.rawRepresentation.count)
                ]
            )
        }

        internal init(validatedRawRepresentation: Data) {
            self.rawRepresentation = Data(validatedRawRepresentation)
        }

        public static func generate() throws -> PrivateKey {
            let fields = [
                OpalCryptoDiagnostics.operationField("private_key_generate"),
                OpalCryptoDiagnostics.algorithmField("secp256k1")
            ]
            do {
                let privateKey = try PrivateKey(
                    rawRepresentation: StandardsForEfficientCryptography256k1CurveModel.Operation
                        .generatePrivateKeyData32Bytes()
                )
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.privateKeyGenerateSucceeded,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + [
                        OpalCryptoDiagnostics.outputLengthField(privateKey.rawRepresentation.count)
                    ]
                )
                return privateKey
            } catch let error as StandardsForEfficientCryptography256k1CurveModel.Operation.Error {
                let mappedError = OpalCrypto.Secp256k1.mapOperationError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.privateKeyGenerateFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.privateKeyGenerateFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
            }
        }
    }
}
