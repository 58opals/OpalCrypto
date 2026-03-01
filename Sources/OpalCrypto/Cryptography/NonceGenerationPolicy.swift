// NonceGenerationPolicy.swift

import Foundation

public enum NonceGenerationPolicy: Sendable, Equatable {
    case requestForComments6979BitcoinCashDefault
    case bitcoinImprovementProposalSchnorrDeterministic
    case systemRandom
}
