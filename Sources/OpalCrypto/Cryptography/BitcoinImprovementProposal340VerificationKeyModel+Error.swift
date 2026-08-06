// BitcoinImprovementProposal340VerificationKeyModel+Error.swift

extension BitcoinImprovementProposal340VerificationKeyModel {
    enum Error: Swift.Error, Equatable {
        case invalidLength(actual: Int)
        case invalidPoint
    }
}
