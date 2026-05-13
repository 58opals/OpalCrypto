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
            do {
                parsedPublicKeyModel = try ParsedPublicKeyModel(publicKeyData: rawRepresentation)
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyLength(let actual) {
                throw Error.invalidPublicKeyLength(
                    expected: expectedSecp256k1PublicKeyLength(for: rawRepresentation),
                    actual: actual
                )
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyPrefix(let actual) {
                throw Error.invalidPublicKeyPrefix(actual: actual)
            } catch {
                throw Error.invalidPublicKey
            }
        }

        internal init(parsedPublicKeyModel: ParsedPublicKeyModel) {
            self.parsedPublicKeyModel = parsedPublicKeyModel
        }

        internal init(verificationKeyModel: VerificationKeyModel) {
            self.parsedPublicKeyModel = verificationKeyModel.parsedPublicKeyModel
        }
    }
}
