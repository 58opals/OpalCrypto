// OpalCrypto.Signature+VerificationKey.swift

import Foundation

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
            let fields = Self.parseFields(inputByteCount: rawRepresentation.count)
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
            inputByteCount: Int
        ) -> [OpalCryptoDiagnostics.Field] {
            [
                OpalCryptoDiagnostics.operationField("verification_key_parse"),
                OpalCryptoDiagnostics.algorithmField("secp256k1"),
                OpalCryptoDiagnostics.inputLengthField(inputByteCount)
            ]
        }

        private static func recordParseFailed(
            _ error: Swift.Error,
            fields: [OpalCryptoDiagnostics.Field]
        ) {
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.verificationKeyParseFailed,
                category: OpalCryptoDiagnostics.Category.signature,
                fields: fields + OpalCryptoDiagnostics.errorFields(error)
            )
        }

        private func recordParseSucceeded(
            fields: [OpalCryptoDiagnostics.Field]
        ) {
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.verificationKeyParseSucceeded,
                category: OpalCryptoDiagnostics.Category.signature,
                fields: fields + [
                    OpalCryptoDiagnostics.outputLengthField(rawRepresentation.count)
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
