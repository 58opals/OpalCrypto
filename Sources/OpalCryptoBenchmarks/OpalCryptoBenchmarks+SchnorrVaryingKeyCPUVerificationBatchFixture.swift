// OpalCryptoBenchmarks+SchnorrVaryingKeyCPUVerificationBatchFixture.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    struct SchnorrVaryingKeyCPUVerificationBatchFixture: Sendable {
        let signatures: [OpalCrypto.Signature.Schnorr]
        let digests: [OpalCrypto.Signature.Digest]
        let verificationKeys: [OpalCrypto.Signature.VerificationKey]
        let publicKeys: [OpalCrypto.Secp256k1.PublicKey]
        let verificationKeyRawRepresentations: [Data]
        let expectedResults: [Bool]
    }
}
