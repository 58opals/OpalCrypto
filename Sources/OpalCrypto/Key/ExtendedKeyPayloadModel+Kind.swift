// ExtendedKeyPayloadModel+Kind.swift

import Foundation

extension ExtendedKeyPayloadModel {
    internal enum Kind: Sendable, Equatable {
        case privateKey
        case publicKey
    }
}
