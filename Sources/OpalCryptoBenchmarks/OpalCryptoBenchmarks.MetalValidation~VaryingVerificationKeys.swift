// OpalCryptoBenchmarks.MetalValidation~VaryingVerificationKeys.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks.MetalValidation {
    static func validateVaryingVerificationKeys() throws -> Int {
        let recordCount = 256
        var signatures: [OpalCrypto.Signature.Schnorr] = []
        var digests: [OpalCrypto.Signature.Digest] = []
        var verificationKeys: [OpalCrypto.Signature.VerificationKey] = []
        signatures.reserveCapacity(recordCount)
        digests.reserveCapacity(recordCount)
        verificationKeys.reserveCapacity(recordCount)

        for index in 0..<recordCount {
            let privateKey = try makePrivateKey(index: index)
            let signingKey = privateKey.makeSigningKey()
            let digest = try OpalCrypto.Signature.Digest(
                rawRepresentation: OpalCrypto.Hashing.sha256(
                    Data("opalcrypto-metal-varying-validation-\(index)".utf8)
                )
            )
            signatures.append(try signingKey.signSchnorr(digest: digest))
            digests.append(digest)
            verificationKeys.append(signingKey.verificationKey)
        }

        verificationKeys[0] = verificationKeys[1]
        digests[1] = digests[2]
        signatures[2] = signatures[3]
        let cpuResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
            signatures: signatures,
            digests: digests,
            verificationKeys: verificationKeys
        )
        let input = try PerformanceBenchmarkOperations
            .makeMetalSchnorrVaryingKeyVerificationBatchInput(
                signatures: signatures,
                digests: digests,
                expectedResults: cpuResults.map { $0 == 1 },
                verificationKeys: verificationKeys
            )
        let metalChecksum = try OpalCryptoBenchmarks.MetalSchnorrVerificationCore.run(
            varyingKeyBatchInput: input
        )
        print("Metal varying-key Schnorr corpus: \(recordCount)")
        return metalChecksum ^ checksum(cpuResults)
    }


    private static func makePrivateKey(
        index: Int
    ) throws -> OpalCrypto.Secp256k1.PrivateKey {
        var rawRepresentation = Data(repeating: 0, count: 32)
        let scalar = UInt32(index + 1)
        rawRepresentation[28] = UInt8(truncatingIfNeeded: scalar >> 24)
        rawRepresentation[29] = UInt8(truncatingIfNeeded: scalar >> 16)
        rawRepresentation[30] = UInt8(truncatingIfNeeded: scalar >> 8)
        rawRepresentation[31] = UInt8(truncatingIfNeeded: scalar)
        return try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: rawRepresentation
        )
    }

}
