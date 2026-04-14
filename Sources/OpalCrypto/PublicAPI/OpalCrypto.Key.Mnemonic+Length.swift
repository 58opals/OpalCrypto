// OpalCrypto.Key.Mnemonic+Length.swift

import Foundation

extension OpalCrypto.Key.Mnemonic {
    public enum Length: Int, CaseIterable, Sendable {
        case words12 = 12
        case words15 = 15
        case words18 = 18
        case words21 = 21
        case words24 = 24
    }
}
