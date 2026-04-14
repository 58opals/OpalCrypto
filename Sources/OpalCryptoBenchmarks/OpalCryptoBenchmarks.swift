// OpalCryptoBenchmarks.swift

import Foundation
import OpalCrypto

@main
enum OpalCryptoBenchmarks {
    nonisolated static func main() async throws {
        let context = try BenchmarkContext.make()
        var checksum = 0

        print("OpalCryptoBenchmarks")
        print("Release-mode benchmark run")

        checksum ^= try runSyncBenchmark(
            name: "Single compressed public-key derivation",
            iterations: 400
        ) {
            let publicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
                from: context.singlePrivateKey
            )
            return publicKey.count ^ Int(publicKey[0])
        }

        checksum ^= try await runAsyncBenchmark(
            name: "Batch compressed public-key derivation (64)",
            iterations: 20
        ) {
            let publicKeys = try await OpalCrypto.Secp256k1.deriveCompressedPublicKeys(
                from: context.batch64PrivateKeys
            )
            return publicKeys.count ^ Int(publicKeys[0][0])
        }

        checksum ^= try await runAsyncBenchmark(
            name: "Batch compressed public-key derivation (256)",
            iterations: 8
        ) {
            let publicKeys = try await OpalCrypto.Secp256k1.deriveCompressedPublicKeys(
                from: context.batch256PrivateKeys
            )
            return publicKeys.count ^ Int(publicKeys[0][0])
        }

        checksum ^= try await runAsyncBenchmark(
            name: "Batch compressed public-key derivation (256, forced serial)",
            iterations: 8
        ) {
            let publicKeys = try await PerformanceBenchmarkSupportModel
                .deriveCompressedPublicKeysSerial(from: context.batch256PrivateKeys)
            return publicKeys.count ^ Int(publicKeys[0][0])
        }

        checksum ^= try await runAsyncBenchmark(
            name: "Batch compressed public-key derivation (256, forced parallel)",
            iterations: 8
        ) {
            let publicKeys = try await PerformanceBenchmarkSupportModel
                .deriveCompressedPublicKeysParallel(from: context.batch256PrivateKeys)
            return publicKeys.count ^ Int(publicKeys[0][0])
        }

        checksum ^= try await runAsyncBenchmark(
            name: "Batch compressed public-key derivation from scalars (256)",
            iterations: 8
        ) {
            let publicKeys = try await PerformanceBenchmarkSupportModel
                .deriveCompressedPublicKeysFromScalars(from: context.batch256PrivateKeys)
            return publicKeys.count ^ Int(publicKeys[0][0])
        }

        checksum ^= try await runAsyncBenchmark(
            name: "Batch compressed public-key derivation (1024)",
            iterations: 3
        ) {
            let publicKeys = try await OpalCrypto.Secp256k1.deriveCompressedPublicKeys(
                from: context.batch1024PrivateKeys
            )
            return publicKeys.count ^ Int(publicKeys[0][0])
        }

        checksum ^= try await runAsyncBenchmark(
            name: "Batch compressed public-key derivation (1024, forced serial)",
            iterations: 3
        ) {
            let publicKeys = try await PerformanceBenchmarkSupportModel
                .deriveCompressedPublicKeysSerial(from: context.batch1024PrivateKeys)
            return publicKeys.count ^ Int(publicKeys[0][0])
        }

        checksum ^= try await runAsyncBenchmark(
            name: "Batch compressed public-key derivation (1024, forced parallel)",
            iterations: 3
        ) {
            let publicKeys = try await PerformanceBenchmarkSupportModel
                .deriveCompressedPublicKeysParallel(from: context.batch1024PrivateKeys)
            return publicKeys.count ^ Int(publicKeys[0][0])
        }

        checksum ^= try await runAsyncBenchmark(
            name: "Batch compressed public-key derivation from scalars (1024)",
            iterations: 3
        ) {
            let publicKeys = try await PerformanceBenchmarkSupportModel
                .deriveCompressedPublicKeysFromScalars(from: context.batch1024PrivateKeys)
            return publicKeys.count ^ Int(publicKeys[0][0])
        }

        checksum ^= try runSyncBenchmark(
            name: "Batch Jacobian multiplication (256)",
            iterations: 8
        ) {
            try PerformanceBenchmarkSupportModel.multiplyBatchGeneratorScalars(
                from: context.batch256PrivateKeys
            )
        }

        checksum ^= try runSyncBenchmark(
            name: "Batch affine conversion (256)",
            iterations: 8
        ) {
            let publicKeys = try PerformanceBenchmarkSupportModel
                .convertBatchJacobianPointBufferToCompressedPublicKeys(
                    context.batch256JacobianPointBufferModel
                )
            return publicKeys.count ^ Int(publicKeys[0][0])
        }

        checksum ^= try runSyncBenchmark(
            name: "Batch Jacobian multiplication (1024)",
            iterations: 3
        ) {
            try PerformanceBenchmarkSupportModel.multiplyBatchGeneratorScalars(
                from: context.batch1024PrivateKeys
            )
        }

        checksum ^= try runSyncBenchmark(
            name: "Batch affine conversion (1024)",
            iterations: 3
        ) {
            let publicKeys = try PerformanceBenchmarkSupportModel
                .convertBatchJacobianPointBufferToCompressedPublicKeys(
                    context.batch1024JacobianPointBufferModel
                )
            return publicKeys.count ^ Int(publicKeys[0][0])
        }

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

        checksum ^= try runSyncBenchmark(name: "Verification-key construction", iterations: 400) {
            let verificationKey = try OpalCrypto.Signature.VerificationKey(
                publicKey: context.compressedPublicKey
            )
            return verificationKey.publicKey.count ^ Int(verificationKey.publicKey[0])
        }

        checksum ^= try runSyncBenchmark(name: "Parsed public-key construction", iterations: 400) {
            let parsedPublicKey = try PerformanceBenchmarkSupportModel.constructParsedPublicKey(
                publicKey: context.compressedPublicKey
            )
            return parsedPublicKey.count ^ Int(parsedPublicKey[0])
        }

        checksum ^= try runSyncBenchmark(name: "Parsed private-key construction", iterations: 400) {
            let parsedPrivateKey = try PerformanceBenchmarkSupportModel.constructParsedPrivateKey(
                privateKey: context.singlePrivateKey
            )
            return parsedPrivateKey.count ^ Int(parsedPrivateKey[0])
        }

        checksum ^= try runSyncBenchmark(name: "Field sqrt", iterations: 400) {
            let squareRoot = try PerformanceBenchmarkSupportModel.computeFieldSquareRoot(
                fieldElementData32Bytes: context.fieldSquareRootInput
            )
            return squareRoot.count ^ Int(squareRoot[31])
        }

        checksum ^= try runSyncBenchmark(name: "Field quadratic-residue check", iterations: 400) {
            try PerformanceBenchmarkSupportModel.checkFieldQuadraticResidue(
                fieldElementData32Bytes: context.fieldSquareRootInput
            ) ? 1 : 0
        }

        checksum ^= try runSyncBenchmark(name: "Scalar inversion", iterations: 400) {
            let inverse = try PerformanceBenchmarkSupportModel.invertScalar(
                scalarData32Bytes: context.scalarInversionInput
            )
            return inverse.count ^ Int(inverse[0])
        }

        checksum ^= try runSyncBenchmark(name: "Generic point multiplication", iterations: 200) {
            let multipliedPublicKey = try PerformanceBenchmarkSupportModel
                .multiplyVerificationKey(
                    scalarData32Bytes: context.genericPointMultiplicationScalar,
                    verificationKey: context.verificationKey
                )
            return multipliedPublicKey.count ^ Int(multipliedPublicKey.first ?? 0)
        }

        checksum ^= try runSyncBenchmark(name: "Joint multiplication", iterations: 200) {
            let multipliedPublicKey = try PerformanceBenchmarkSupportModel
                .jointMultiplyGeneratorAndVerificationKey(
                    generatorScalarData32Bytes: context.jointGeneratorScalar,
                    verificationKeyScalarData32Bytes: context.jointVerificationKeyScalar,
                    verificationKey: context.verificationKey
                )
            return multipliedPublicKey.count ^ Int(multipliedPublicKey.first ?? 0)
        }

        checksum ^= try runSyncBenchmark(name: "PBKDF2", iterations: 60) {
            let derivedKey = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                password: context.basePayload,
                salt: context.batch64PrivateKeys[0],
                iterationCount: 2048,
                derivedKeyLength: 64
            )
            return derivedKey.count ^ Int(derivedKey[0])
        }

        checksum ^= try runSyncBenchmark(name: "Mnemonic parse", iterations: 200) {
            let mnemonic = try OpalCrypto.Key.Mnemonic(
                phrase: context.mnemonicPhrase,
                language: .english
            )
            return mnemonic.words.count ^ mnemonic.phrase.count
        }

        checksum ^= try runSyncBenchmark(name: "Mnemonic generate", iterations: 60) {
            let mnemonic = try OpalCrypto.Key.Mnemonic.generate(
                length: .words24,
                language: .english
            )
            return mnemonic.words.count ^ mnemonic.phrase.count
        }

        checksum ^= try runSyncBenchmark(name: "Mnemonic seed derivation", iterations: 80) {
            let seed = try context.mnemonic.deriveSeed(passphrase: "benchmark")
            return seed.count ^ Int(seed[0])
        }

        checksum ^= runSyncBenchmark(name: "Base58 encode", iterations: 500) {
            let encoded = OpalCrypto.Encoding.encodeBase58(context.basePayload)
            return encoded.count ^ encoded.utf8.reduce(0) { $0 ^ Int($1) }
        }

        checksum ^= runSyncBenchmark(name: "Base58 decode", iterations: 500) {
            let decoded = OpalCrypto.Encoding.decodeBase58(context.base58EncodedPayload)!
            return decoded.count ^ Int(decoded[0])
        }

        checksum ^= try runSyncBenchmark(name: "Base32 encode", iterations: 500) {
            let encoded = try OpalCrypto.Encoding.encodeBase32(
                context.basePayload,
                interpretedAsFiveBitValues: false
            )
            return encoded.count ^ encoded.utf8.reduce(0) { $0 ^ Int($1) }
        }

        checksum ^= try runSyncBenchmark(name: "Base32 decode", iterations: 500) {
            let decoded = try OpalCrypto.Encoding.decodeBase32(
                context.base32EncodedPayload,
                interpretedAsFiveBitValues: false
            )
            return decoded.count ^ Int(decoded[0])
        }

        checksum ^= try runSyncBenchmark(name: "Extended-key derivation", iterations: 120) {
            let child = try context.rootExtendedPrivate.derived(
                indices: [0x8000_0000, 1, 2, 3]
            )
            return Int(child.depth) ^ Int(child.privateKey[0])
        }

        checksum ^= try runSyncBenchmark(
            name: "Extended private-key derivation (single hop)",
            iterations: 200
        ) {
            let child = try context.rootExtendedPrivate.derived(indices: [1])
            return Int(child.depth) ^ Int(child.privateKey[0])
        }

        checksum ^= try runSyncBenchmark(
            name: "Extended public-key derivation (single hop)",
            iterations: 200
        ) {
            let child = try context.rootExtendedPublic.derived(indices: [1])
            return Int(child.depth) ^ Int(child.publicKey[0])
        }

        checksum ^= try runSyncBenchmark(
            name: "Extended public-key derivation (repeated)",
            iterations: 120
        ) {
            let child = try context.rootExtendedPublic.derived(indices: [1, 2, 3, 4])
            return Int(child.depth) ^ Int(child.publicKey[0])
        }

        print("Checksum: \(checksum)")
    }

    private static func runSyncBenchmark(
        name: String,
        iterations: Int,
        operation: () throws -> Int
    ) rethrows -> Int {
        let startNanoseconds = DispatchTime.now().uptimeNanoseconds
        var checksum = 0
        for _ in 0..<iterations {
            checksum ^= try operation()
        }
        let elapsedNanoseconds = DispatchTime.now().uptimeNanoseconds - startNanoseconds
        printSummary(
            name: name,
            iterations: iterations,
            elapsedNanoseconds: elapsedNanoseconds
        )
        return checksum
    }

    private static func runAsyncBenchmark(
        name: String,
        iterations: Int,
        operation: @Sendable () async throws -> Int
    ) async rethrows -> Int {
        let startNanoseconds = DispatchTime.now().uptimeNanoseconds
        var checksum = 0
        for _ in 0..<iterations {
            checksum ^= try await operation()
        }
        let elapsedNanoseconds = DispatchTime.now().uptimeNanoseconds - startNanoseconds
        printSummary(
            name: name,
            iterations: iterations,
            elapsedNanoseconds: elapsedNanoseconds
        )
        return checksum
    }

    private static func printSummary(
        name: String,
        iterations: Int,
        elapsedNanoseconds: UInt64
    ) {
        let totalMilliseconds = Double(elapsedNanoseconds) / 1_000_000
        let averageMicroseconds = Double(elapsedNanoseconds) / Double(iterations) / 1_000
        let totalText = totalMilliseconds.formatted(
            .number.precision(.fractionLength(3))
        )
        let averageText = averageMicroseconds.formatted(
            .number.precision(.fractionLength(3))
        )
        print("\(name): total \(totalText) ms, avg \(averageText) us")
    }
}
