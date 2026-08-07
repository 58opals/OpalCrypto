// NostrImplementationPossibility44Model+ParsedPayload.swift

import Foundation

extension NostrImplementationPossibility44Model {
    struct ParsedPayload: Sendable, Equatable {
        let nonce: Data
        let ciphertext: Data
        let authenticationCode: Data
    }
}
