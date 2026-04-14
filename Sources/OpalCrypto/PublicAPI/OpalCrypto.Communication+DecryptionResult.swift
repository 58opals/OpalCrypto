// OpalCrypto.Communication+DecryptionResult.swift

import Foundation

extension OpalCrypto.Communication {
    public struct DecryptionResult: Sendable, Equatable {
        public let message: Data
        public let symmetricKey: Data

        internal init(resultModel: CommunicationBoxModel.DecryptionResult) {
            self.message = resultModel.message
            self.symmetricKey = resultModel.symmetricKey
        }
    }
}
