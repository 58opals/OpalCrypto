// NostrImplementationPossibility44Model+MessageKeys.swift

import Foundation

extension NostrImplementationPossibility44Model {
    struct MessageKeys: Sendable, Equatable {
        let chachaKey: Data
        let chachaNonce: Data
        let authenticationKey: Data
    }
}
