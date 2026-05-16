// CommunicationBoxModel+DecryptionResult.swift

import Foundation

extension CommunicationBoxModel {
    struct DecryptionResult: Sendable, Equatable {
        let message: Data
        let symmetricKey: Data
    }
}
