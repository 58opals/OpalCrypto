// OpalCrypto.Pedersen+Nonce.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Pedersen {
    public struct Nonce: Sendable, Equatable {
        internal let scalarModel: ScalarModel

        public var rawRepresentation: Data {
            scalarModel.data32Bytes
        }

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("nonce_parse"),
                OpalDiagnostics.Field.inputLengthField(rawRepresentation.count)
            ]
            do {
                scalarModel = try ScalarModel(data32: rawRepresentation, requireNonZero: false)
            } catch ScalarModel.Error.invalidDataLength(let expected, let actual) {
                precondition(expected == 32)
                let mappedError = Error.invalidNonceLength(expected: expected, actual: actual)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenNonceParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenNonceParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            } catch {
                let mappedError = Error.invalidNonce
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenNonceParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenNonceParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                event: OpalDiagnostics.Event.pedersenNonceParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenNonceParseSucceeded),
                fields: fields
            )
        }

        internal init(scalarModel: ScalarModel) {
            self.scalarModel = scalarModel
        }
    }
}
