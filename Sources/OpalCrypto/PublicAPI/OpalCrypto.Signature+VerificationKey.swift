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
            do {
                self.init(
                    publicKey: try OpalCrypto.Secp256k1.PublicKey(
                        rawRepresentation: rawRepresentation
                    )
                )
            } catch let error as OpalCrypto.Secp256k1.Error {
                throw OpalCrypto.Signature.mapCryptographyError(error)
            }
        }

        internal init(rawPublicKey: Data) throws {
            do {
                verificationKeyModel = try VerificationKeyModel(publicKeyData: rawPublicKey)
            } catch VerificationKeyModel.Error.invalidPublicKeyLength(let actual) {
                throw Error.invalidPublicKeyLength(actual: actual)
            } catch VerificationKeyModel.Error.invalidPublicKeyPrefix(let actual) {
                throw Error.invalidPublicKeyPrefix(actual: actual)
            } catch {
                throw Error.invalidPublicKey
            }
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
