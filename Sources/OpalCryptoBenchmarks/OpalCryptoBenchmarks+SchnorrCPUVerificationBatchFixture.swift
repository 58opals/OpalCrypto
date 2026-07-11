// OpalCryptoBenchmarks+SchnorrCPUVerificationBatchFixture.swift

import OpalCrypto

extension OpalCryptoBenchmarks {
    struct SchnorrCPUVerificationBatchFixture: Sendable {
        let signatures: [OpalCrypto.Signature.Schnorr]
        let digests: [OpalCrypto.Signature.Digest]
        let expectedResults: [Bool]
    }
}
