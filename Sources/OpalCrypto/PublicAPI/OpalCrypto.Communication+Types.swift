// OpalCrypto.Communication+Types.swift

import Foundation

extension OpalCrypto.Communication {
    public struct Ciphertext: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count >= CommunicationBoxModel.minimumCiphertextLength else {
                throw Error.invalidCiphertext
            }
            let ephemeralPublicKey = Data(rawRepresentation.prefix(33))
            do {
                try CommunicationBoxModel.validateCompressedPublicKey(ephemeralPublicKey)
                _ = try StandardsForEfficientCryptography256k1CurveModel.Operation
                    .parsePublicKeyAffine(ephemeralPublicKey)
            } catch {
                throw Error.invalidCiphertext
            }

            let encryptedPayload = rawRepresentation.dropFirst(33).dropLast(16)
            guard !encryptedPayload.isEmpty, encryptedPayload.count.isMultiple(of: 16) else {
                throw Error.invalidCiphertext
            }
            self.rawRepresentation = rawRepresentation
        }

        internal init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }
    }

    public struct SymmetricKey: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            guard rawRepresentation.count == 32 else {
                throw Error.invalidSymmetricKeyLength(expected: 32, actual: rawRepresentation.count)
            }
            self.rawRepresentation = rawRepresentation
        }
    }
}
