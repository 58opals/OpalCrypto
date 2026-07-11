// MetalSchnorrVerificationKeySource.swift

import Foundation

enum MetalSchnorrVerificationKeySource: Sendable {
    case prepared([OpalCrypto.Signature.VerificationKey])
    case rawRepresentations([Data])

    var count: Int {
        switch self {
        case .prepared(let verificationKeys):
            verificationKeys.count
        case .rawRepresentations(let rawRepresentations):
            rawRepresentations.count
        }
    }

    func parsedPublicKeyModel(at index: Int) throws -> ParsedPublicKeyModel {
        switch self {
        case .prepared(let verificationKeys):
            verificationKeys[index].verificationKeyModel.parsedPublicKeyModel
        case .rawRepresentations(let rawRepresentations):
            try ParsedPublicKeyModel(publicKeyData: rawRepresentations[index])
        }
    }
}
