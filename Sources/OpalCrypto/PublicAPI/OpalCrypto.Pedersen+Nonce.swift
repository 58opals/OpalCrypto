// OpalCrypto.Pedersen+Nonce.swift

import Foundation

extension OpalCrypto.Pedersen {
    public struct Nonce: Sendable, Equatable {
        internal let scalarModel: ScalarModel

        public var rawRepresentation: Data {
            scalarModel.data32Bytes
        }

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalCryptoDiagnostics.operationField("nonce_parse"),
                OpalCryptoDiagnostics.inputLengthField(rawRepresentation.count)
            ]
            do {
                scalarModel = try ScalarModel(data32: rawRepresentation, requireNonZero: false)
            } catch ScalarModel.Error.invalidDataLength(let expected, let actual) {
                precondition(expected == 32)
                let mappedError = Error.invalidNonceLength(expected: expected, actual: actual)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenNonceParseFailed,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch {
                let mappedError = Error.invalidNonce
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenNonceParseFailed,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.pedersenNonceParseSucceeded,
                category: OpalCryptoDiagnostics.Category.pedersen,
                fields: fields
            )
        }

        internal init(scalarModel: ScalarModel) {
            self.scalarModel = scalarModel
        }
    }
}
