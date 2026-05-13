// OpalCrypto.Communication+Ciphertext.swift

import Foundation

extension OpalCrypto.Communication {
    public struct Ciphertext: Sendable, Equatable {
        public let rawRepresentation: Data

        public init(rawRepresentation: Data) throws {
            do {
                try CommunicationBoxModel.validateCiphertextEnvelope(rawRepresentation)
            } catch {
                throw Error.invalidCiphertext
            }
            self.rawRepresentation = rawRepresentation
        }

        internal init(unchecked rawRepresentation: Data) {
            self.rawRepresentation = rawRepresentation
        }
    }
}
