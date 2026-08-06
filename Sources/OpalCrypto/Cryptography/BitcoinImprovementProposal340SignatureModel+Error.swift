// BitcoinImprovementProposal340SignatureModel+Error.swift

extension BitcoinImprovementProposal340SignatureModel {
    enum Error: Swift.Error, Equatable {
        case nonceIsZero
        case pointAtInfinity
        case selfVerificationFailed
    }
}
