// OpalCryptoBenchmarks~SignatureBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func runSignatureBenchmarks(context: BenchmarkContext) throws -> Int {
        var checksum = 0

        checksum ^= try runSyncBenchmark(name: "ECDSA sign", iterations: 200) {
            let signature = try OpalCrypto.Signature.signECDSA(
                message: context.ecdsaMessage,
                privateKey: context.singlePrivateKey,
                format: .der
            )
            return signature.count ^ Int(signature[0])
        }

        checksum ^= try runSyncBenchmark(name: "ECDSA verify", iterations: 200) {
            let isValid = try OpalCrypto.Signature.verifyECDSA(
                signature: context.ecdsaSignature,
                message: context.ecdsaMessage,
                publicKey: context.compressedPublicKey,
                format: .der
            )
            return isValid ? 1 : 0
        }

        checksum ^= try runSyncBenchmark(name: "ECDSA verify (cached key)", iterations: 200) {
            let isValid = try OpalCrypto.Signature.verifyECDSA(
                signature: context.ecdsaSignature,
                message: context.ecdsaMessage,
                verificationKey: context.verificationKey,
                format: .der
            )
            return isValid ? 1 : 0
        }

        checksum ^= try runSyncBenchmark(name: "Schnorr sign", iterations: 200) {
            let signature = try OpalCrypto.Signature.signSchnorr(
                digest: context.schnorrDigest,
                privateKey: context.singlePrivateKey,
                noncePolicy: .bip340Deterministic
            )
            return signature.count ^ Int(signature[0])
        }

        checksum ^= try runSyncBenchmark(name: "Schnorr verify", iterations: 200) {
            let isValid = try OpalCrypto.Signature.verifySchnorr(
                signature: context.schnorrSignature,
                digest: context.schnorrDigest,
                publicKey: context.compressedPublicKey
            )
            return isValid ? 1 : 0
        }

        checksum ^= try runSyncBenchmark(name: "Schnorr verify (cached key)", iterations: 200) {
            let isValid = try OpalCrypto.Signature.verifySchnorr(
                signature: context.schnorrSignature,
                digest: context.schnorrDigest,
                verificationKey: context.verificationKey
            )
            return isValid ? 1 : 0
        }

        return checksum
    }
}
