// OpalCrypto.Secp256k1+PublicKey.swift

import Foundation

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
                OpalCryptoDiagnostics.operationField("public_key_parse"),
                OpalCryptoDiagnostics.formatField(Self.diagnosticsFormat(for: rawRepresentation)),
                OpalCryptoDiagnostics.inputLengthField(rawRepresentation.count)
            ]
            do {
                parsedPublicKeyModel = try Self.parsePublicKeyModel(rawRepresentation)
            } catch let mappedError as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.publicKeyParseFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch {
                let mappedError = Error.invalidPublicKey
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.publicKeyParseFailed,
                    category: OpalCryptoDiagnostics.Category.key,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.publicKeyParseSucceeded,
                category: OpalCryptoDiagnostics.Category.key,
                fields: fields + [
                    OpalCryptoDiagnostics.outputLengthField(parsedPublicKeyModel.compressedPublicKeyData.count)
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

        private static func diagnosticsFormat(for rawRepresentation: Data) -> String {
            switch rawRepresentation.first {
            case 0x02, 0x03:
                return "sec1_compressed"
            case 0x04:
                return "sec1_uncompressed"
            case .some:
                return "sec1_unknown"
            case .none:
                return "sec1_empty"
            }
        }
    }
}
