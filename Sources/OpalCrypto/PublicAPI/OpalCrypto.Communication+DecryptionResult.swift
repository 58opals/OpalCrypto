// OpalCrypto.Communication+DecryptionResult.swift

import Foundation

extension OpalCrypto.Communication {
    public struct DecryptionResult: Sendable, Equatable {
        public let message: Data
        public let symmetricKey: SymmetricKey

        internal init(resultModel: CommunicationBoxModel.DecryptionResult) {
            self.message = resultModel.message
            self.symmetricKey = try! SymmetricKey(rawRepresentation: resultModel.symmetricKey)
        }
    }
}
