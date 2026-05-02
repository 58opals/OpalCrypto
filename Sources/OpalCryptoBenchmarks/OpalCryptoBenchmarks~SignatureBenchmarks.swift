// OpalCryptoBenchmarks~SignatureBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func runSignatureBenchmarks(context: BenchmarkContext) throws -> Int {
        var checksum = 0

        checksum ^= try runSyncBenchmark(name: "ECDSA sign", iterations: 200) {
            let signature = try OpalCrypto.Signature.ECDSA.sign(
                message: context.ecdsaMessage,
                privateKey: context.singlePrivateKeyValue,
                format: .der
            )
            return signature.rawRepresentation.count ^ Int(signature.rawRepresentation[0])
        }

        checksum ^= try runSyncBenchmark(name: "ECDSA verify", iterations: 200) {
            let isValid = try context.ecdsaSignature.verify(
                message: context.ecdsaMessage,
                publicKey: context.compressedPublicKey
            )
            return isValid ? 1 : 0
        }

        checksum ^= try runSyncBenchmark(name: "ECDSA verify (cached key)", iterations: 200) {
            let isValid = try context.ecdsaSignature.verify(
                message: context.ecdsaMessage,
                verificationKey: context.verificationKey
            )
            return isValid ? 1 : 0
        }

        checksum ^= try runSyncBenchmark(name: "Schnorr sign", iterations: 200) {
            let signature = try OpalCrypto.Signature.Schnorr.sign(
                digest: context.schnorrDigest,
                privateKey: context.singlePrivateKeyValue,
                noncePolicy: .bip340Deterministic
            )
            return signature.rawRepresentation.count ^ Int(signature.rawRepresentation[0])
        }

        checksum ^= try runSyncBenchmark(name: "Schnorr verify", iterations: 200) {
            let isValid = try context.schnorrSignature.verify(
                digest: context.schnorrDigest,
                publicKey: context.compressedPublicKey
            )
            return isValid ? 1 : 0
        }

        checksum ^= try runSyncBenchmark(name: "Schnorr verify (cached key)", iterations: 200) {
            let isValid = try context.schnorrSignature.verify(
                digest: context.schnorrDigest,
                verificationKey: context.verificationKey
            )
            return isValid ? 1 : 0
        }

        return checksum
    }
}
