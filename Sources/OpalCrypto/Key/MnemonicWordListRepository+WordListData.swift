// MnemonicWordListRepository+WordListData.swift

import Foundation

extension MnemonicWordListRepository {
    internal struct WordListData: Sendable, Equatable {
        internal let words: [String]
        internal let indexLookup: [String: Int]
    }
}
