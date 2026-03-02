// NonceGenerationPolicy.swift

import Foundation

internal enum NonceGenerationPolicy: Sendable, Equatable {
    case requestForComments6979BitcoinCashDefault
    case bitcoinImprovementProposalSchnorrDeterministic
    case systemRandom
}
