// OpalCrypto.Key.Mnemonic+Word.swift

import Foundation

extension OpalCrypto.Key.Mnemonic {
    /// A normalized BIP-39 mnemonic word.
    public struct Word: Sendable, Hashable, LosslessStringConvertible {

        public let text: String

        /// Creates a word by applying the mnemonic word normalization rules.
        public init(_ description: String) {
            self.text = MnemonicCodecModel.normalizeWord(description)
        }

        public var description: String {
            text
        }
    }
}
