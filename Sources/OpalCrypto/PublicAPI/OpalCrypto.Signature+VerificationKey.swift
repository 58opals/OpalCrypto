// OpalCrypto.Signature+VerificationKey.swift

import Foundation

extension OpalCrypto.Signature {
    public struct VerificationKey: Sendable, Equatable {

        internal let verificationKeyModel: VerificationKeyModel

        public var publicKey: Data {
            verificationKeyModel.compressedPublicKeyData
        }

        public init(publicKey: Data) throws {
            do {
                verificationKeyModel = try VerificationKeyModel(publicKeyData: publicKey)
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
            lhs.publicKey == rhs.publicKey
        }
    }
}
