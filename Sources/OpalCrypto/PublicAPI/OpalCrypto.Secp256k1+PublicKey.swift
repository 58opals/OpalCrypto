// OpalCrypto.Secp256k1+PublicKey.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Secp256k1 {
    public struct PublicKey: Sendable, Equatable {
        internal let parsedPublicKeyModel: ParsedPublicKeyModel

        public var rawRepresentation: Data {
            parsedPublicKeyModel.compressedPublicKeyData
        }

        public var compressedRepresentation: Data {
            parsedPublicKeyModel.compressedPublicKeyData
        }

        public var uncompressedRepresentation: Data {
            parsedPublicKeyModel.affinePoint.encodeUncompressed65()
        }

        public init(rawRepresentation: Data) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("public_key_parse"),
                OpalDiagnostics.Field.formatField(
                    PublicKeyParserModel.sec1DiagnosticsFormat(for: rawRepresentation)
                ),
                OpalDiagnostics.Field.inputLengthField(rawRepresentation.count)
            ]
            do {
                parsedPublicKeyModel = try Self.parsePublicKeyModel(rawRepresentation)
            } catch let mappedError as Error {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.publicKeyParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeyParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            } catch {
                let mappedError = Error.invalidPublicKey
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                    event: OpalDiagnostics.Event.publicKeyParseFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeyParseFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
                event: OpalDiagnostics.Event.publicKeyParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.publicKeyParseSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(parsedPublicKeyModel.compressedPublicKeyData.count)
                ]
            )
        }

        internal init(parsedPublicKeyModel: ParsedPublicKeyModel) {
            self.parsedPublicKeyModel = parsedPublicKeyModel
        }

        internal init(validatingRawRepresentation rawRepresentation: Data) throws {
            self.parsedPublicKeyModel = try Self.parsePublicKeyModel(rawRepresentation)
        }

        internal init(verificationKeyModel: VerificationKeyModel) {
            self.parsedPublicKeyModel = verificationKeyModel.parsedPublicKeyModel
        }

        private static func parsePublicKeyModel(
            _ rawRepresentation: Data
        ) throws -> ParsedPublicKeyModel {
            do {
                return try ParsedPublicKeyModel(publicKeyData: rawRepresentation)
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyLength(let actual) {
                throw Error.invalidPublicKeyLength(
                    expected: PublicKeyParserModel.expectedSec1PublicKeyLength(for: rawRepresentation),
                    actual: actual
                )
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyPrefix(let actual) {
                throw Error.invalidPublicKeyPrefix(actual: actual)
            } catch {
                throw Error.invalidPublicKey
            }
        }

    }
}
