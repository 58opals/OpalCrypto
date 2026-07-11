// MetalSchnorrCachedKeyContext.swift

import Foundation

struct MetalSchnorrCachedKeyContext: Sendable {
    let verificationKeyModel: VerificationKeyModel
    let tableIdentifier: Data
    let tableWords: [UInt32]
}
