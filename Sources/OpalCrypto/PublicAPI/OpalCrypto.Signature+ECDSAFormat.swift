// OpalCrypto.Signature+ECDSAFormat.swift

import Foundation

extension OpalCrypto.Signature {
    public enum ECDSAFormat: Sendable, Equatable {
        case raw
        case der
    }
}
