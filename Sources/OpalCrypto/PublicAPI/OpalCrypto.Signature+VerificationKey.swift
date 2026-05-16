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
            let fields = [
                OpalCryptoDiagnostics.operationField("verification_key_parse"),
                OpalCryptoDiagnostics.algorithmField("secp256k1"),
                OpalCryptoDiagnostics.inputLengthField(rawRepresentation.count)
            ]
            do {
                self.init(
                    publicKey: try OpalCrypto.Secp256k1.PublicKey(
                        rawRepresentation: rawRepresentation
                    )
                )
            } catch let error as OpalCrypto.Secp256k1.Error {
                let mappedError = OpalCrypto.Signature.mapCryptographyError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.verificationKeyParseFailed,
                    category: OpalCryptoDiagnostics.Category.signature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.verificationKeyParseSucceeded,
                category: OpalCryptoDiagnostics.Category.signature,
                fields: fields + [
                    OpalCryptoDiagnostics.outputLengthField(rawRepresentation.count)
                ]
            )
        }

        internal init(rawPublicKey: Data) throws {
            let fields = [
                OpalCryptoDiagnostics.operationField("verification_key_parse"),
                OpalCryptoDiagnostics.algorithmField("secp256k1"),
                OpalCryptoDiagnostics.inputLengthField(rawPublicKey.count)
            ]
            do {
                verificationKeyModel = try VerificationKeyModel(publicKeyData: rawPublicKey)
            } catch VerificationKeyModel.Error.invalidPublicKeyLength(let actual) {
                let mappedError = Error.invalidPublicKeyLength(actual: actual)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.verificationKeyParseFailed,
                    category: OpalCryptoDiagnostics.Category.signature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch VerificationKeyModel.Error.invalidPublicKeyPrefix(let actual) {
                let mappedError = Error.invalidPublicKeyPrefix(actual: actual)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.verificationKeyParseFailed,
                    category: OpalCryptoDiagnostics.Category.signature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch {
                let mappedError = Error.invalidPublicKey
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.verificationKeyParseFailed,
                    category: OpalCryptoDiagnostics.Category.signature,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.verificationKeyParseSucceeded,
                category: OpalCryptoDiagnostics.Category.signature,
                fields: fields + [
                    OpalCryptoDiagnostics.outputLengthField(rawPublicKey.count)
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
