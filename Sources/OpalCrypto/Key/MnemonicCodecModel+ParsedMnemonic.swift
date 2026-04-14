// MnemonicCodecModel+ParsedMnemonic.swift

import Foundation

extension MnemonicCodecModel {
    internal struct ParsedMnemonic: Sendable, Equatable {
        internal let words: [String]
        internal let length: OpalCrypto.Key.Mnemonic.Length
        internal let language: OpalCrypto.Key.Mnemonic.Word.Language
    }
}
