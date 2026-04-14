// OpalCrypto.Key.Mnemonic+Word.swift

import Foundation

extension OpalCrypto.Key.Mnemonic {
    public struct Word: Sendable, Hashable, LosslessStringConvertible {

        public let text: String

        public init(_ description: String) {
            self.text = MnemonicCodecModel.normalizeWord(description)
        }

        public var description: String {
            text
        }
    }
}
