// OpalCrypto.Signature+VerificationKey.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Signature {
    public struct VerificationKey: Sendable, Equatable {

        internal let verificationKeyModel: VerificationKeyModel

        public var rawRepresentation: Data {
            publicKey.rawRepresentation
        }

        public var publicKey: OpalCrypto.Secp256k1.PublicKey {
            OpalCrypto.Secp256k1.PublicKey(verificationKeyModel: verificationKeyModel)
        }

        public init(publicKey: OpalCrypto.Secp256k1.PublicKey) {
            verificationKeyModel = VerificationKeyModel(
                parsedPublicKeyModel: publicKey.parsedPublicKeyModel
            )
        }

        public init(rawRepresentation: Data) throws {
            let fields = Self.parseFields(rawRepresentation: rawRepresentation)
            do {
                verificationKeyModel = try VerificationKeyModel(publicKeyData: rawRepresentation)
            } catch VerificationKeyModel.Error.invalidPublicKeyLength(let actual) {
                let mappedError = OpalCrypto.Signature.Error.invalidPublicKeyLength(
                    expected: PublicKeyParserModel.expectedSec1PublicKeyLength(for: rawRepresentation),
                    actual: actual
                )
                Self.recordParseFailed(mappedError, fields: fields)
                throw mappedError
            } catch VerificationKeyModel.Error.invalidPublicKeyPrefix(let actual) {
                let mappedError = OpalCrypto.Signature.Error.invalidPublicKeyPrefix(actual: actual)
                Self.recordParseFailed(mappedError, fields: fields)
                throw mappedError
            } catch {
                let mappedError = OpalCrypto.Signature.Error.invalidPublicKey
                Self.recordParseFailed(mappedError, fields: fields)
                throw mappedError
            }
            recordParseSucceeded(fields: fields)
        }

        private static func parseFields(
            rawRepresentation: Data
        ) -> [OpalDiagnostics.Field] {
            [
                OpalDiagnostics.Field.operationField("verification_key_parse"),
                OpalDiagnostics.Field.algorithmField("secp256k1"),
                OpalDiagnostics.Field.formatField(
                    PublicKeyParserModel.sec1DiagnosticsFormat(for: rawRepresentation)
                ),
                OpalDiagnostics.Field.inputLengthField(rawRepresentation.count)
            ]
        }

        private static func recordParseFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.verificationKeyParseFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.verificationKeyParseFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
        }

        private func recordParseSucceeded(
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.verificationKeyParseSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.verificationKeyParseSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(rawRepresentation.count)
                ]
            )
        }

        internal init(verificationKeyModel: VerificationKeyModel) {
            self.verificationKeyModel = verificationKeyModel
        }

        public static func == (
            lhs: VerificationKey,
            rhs: VerificationKey
        ) -> Bool {
            lhs.publicKey.rawRepresentation == rhs.publicKey.rawRepresentation
        }
    }
}
