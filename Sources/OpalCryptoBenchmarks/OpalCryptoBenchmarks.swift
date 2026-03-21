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

        checksum ^= try runSyncBenchmark(name: "ECDSA sign", iterations: 200) {
            let signature = try OpalCrypto.Signature.sign(
                message: context.ecdsaMessage,
                privateKey: context.singlePrivateKey,
                format: .ecdsa(.der)
            )
            return signature.count ^ Int(signature[0])
        }

        checksum ^= try runSyncBenchmark(name: "ECDSA verify", iterations: 200) {
            let isValid = try OpalCrypto.Signature.verify(
                signature: context.ecdsaSignature,
                message: context.ecdsaMessage,
                publicKey: context.compressedPublicKey,
                format: .ecdsa(.der)
            )
            return isValid ? 1 : 0
        }

        checksum ^= try runSyncBenchmark(name: "ECDSA verify (cached key)", iterations: 200) {
            let isValid = try OpalCrypto.Signature.verify(
                signature: context.ecdsaSignature,
                message: context.ecdsaMessage,
                verificationKey: context.verificationKey,
                format: .ecdsa(.der)
            )
            return isValid ? 1 : 0
        }

        checksum ^= try runSyncBenchmark(name: "Schnorr sign", iterations: 200) {
            let signature = try OpalCrypto.Signature.sign(
                message: context.schnorrDigest,
                privateKey: context.singlePrivateKey,
                format: .schnorr,
                nonce: .bip340Deterministic
            )
            return signature.count ^ Int(signature[0])
        }

        checksum ^= try runSyncBenchmark(name: "Schnorr verify", iterations: 200) {
            let isValid = try OpalCrypto.Signature.verify(
                signature: context.schnorrSignature,
                message: context.schnorrDigest,
                publicKey: context.compressedPublicKey,
                format: .schnorr
            )
            return isValid ? 1 : 0
        }

        checksum ^= try runSyncBenchmark(name: "Schnorr verify (cached key)", iterations: 200) {
            let isValid = try OpalCrypto.Signature.verify(
                signature: context.schnorrSignature,
                message: context.schnorrDigest,
                verificationKey: context.verificationKey,
                format: .schnorr
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
            let child = try context.rootExtendedPrivateKey.derived(
                indices: [0x8000_0000, 1, 2, 3]
            )
            return Int(child.depth) ^ Int(child.privateKey[0])
        }

        checksum ^= try runSyncBenchmark(
            name: "Extended private-key derivation (single hop)",
            iterations: 200
        ) {
            let child = try context.rootExtendedPrivateKey.derived(indices: [1])
            return Int(child.depth) ^ Int(child.privateKey[0])
        }

        checksum ^= try runSyncBenchmark(
            name: "Extended public-key derivation (single hop)",
            iterations: 200
        ) {
            let child = try context.rootExtendedPublicKey.derived(indices: [1])
            return Int(child.depth) ^ Int(child.publicKey[0])
        }

        checksum ^= try runSyncBenchmark(
            name: "Extended public-key derivation (repeated)",
            iterations: 120
        ) {
            let child = try context.rootExtendedPublicKey.derived(indices: [1, 2, 3, 4])
            return Int(child.depth) ^ Int(child.publicKey[0])
        }

        print("Checksum: \(checksum)")
    }

    private struct BenchmarkContext: Sendable {
        let singlePrivateKey: Data
        let batch64PrivateKeys: [Data]
        let batch256PrivateKeys: [Data]
        let batch1024PrivateKeys: [Data]
        let ecdsaMessage: Data
        let schnorrDigest: Data
        let compressedPublicKey: Data
        let verificationKey: OpalCrypto.Signature.VerificationKey
        let ecdsaSignature: Data
        let schnorrSignature: Data
        let mnemonic: OpalCrypto.Key.Mnemonic
        let mnemonicPhrase: String
        let basePayload: Data
        let base58EncodedPayload: String
        let base32EncodedPayload: String
        let rootExtendedPrivateKey: OpalCrypto.Key.ExtendedPrivateKey
        let rootExtendedPublicKey: OpalCrypto.Key.ExtendedPublicKey
        let genericPointMultiplicationScalar: Data
        let jointGeneratorScalar: Data
        let jointVerificationKeyScalar: Data

        static func make() throws -> BenchmarkContext {
            let singlePrivateKey = makePrivateKey(index: 1)
            let batch64PrivateKeys = (1...64).map(makePrivateKey(index:))
            let batch256PrivateKeys = (1...256).map(makePrivateKey(index:))
            let batch1024PrivateKeys = (1...1024).map(makePrivateKey(index:))
            let ecdsaMessage = Data("opalcrypto-benchmark-ecdsa".utf8)
            let schnorrDigest = OpalCrypto.Hashing.computeSHA256(
                Data("opalcrypto-benchmark-schnorr".utf8)
            )
            let compressedPublicKey = try OpalCrypto.Signature.derivePublicKey(
                fromPrivateKey: singlePrivateKey
            )
            let verificationKey = try OpalCrypto.Signature.deriveVerificationKey(
                fromPrivateKey: singlePrivateKey
            )
            let ecdsaSignature = try OpalCrypto.Signature.sign(
                message: ecdsaMessage,
                privateKey: singlePrivateKey,
                format: .ecdsa(.der)
            )
            let schnorrSignature = try OpalCrypto.Signature.sign(
                message: schnorrDigest,
                privateKey: singlePrivateKey,
                format: .schnorr,
                nonce: .bip340Deterministic
            )
            let mnemonic = try OpalCrypto.Key.Mnemonic(
                phrase: """
                abandon abandon abandon abandon abandon abandon
                abandon abandon abandon abandon abandon about
                """,
                language: .english
            )
            let basePayload = Data((0..<64).map { UInt8(($0 * 17) & 0xff) })
            let base58EncodedPayload = OpalCrypto.Encoding.encodeBase58(basePayload)
            let base32EncodedPayload = try OpalCrypto.Encoding.encodeBase32(
                basePayload,
                interpretedAsFiveBitValues: false
            )
            let rootExtendedPrivateKey = try OpalCrypto.Key.ExtendedPrivateKey.root(
                seed: try mnemonic.deriveSeed(passphrase: "benchmark")
            )
            let rootExtendedPublicKey = rootExtendedPrivateKey.publicKey
            let genericPointMultiplicationScalar = makePrivateKey(index: 17)
            let jointGeneratorScalar = makePrivateKey(index: 19)
            let jointVerificationKeyScalar = makePrivateKey(index: 23)

            return BenchmarkContext(
                singlePrivateKey: singlePrivateKey,
                batch64PrivateKeys: batch64PrivateKeys,
                batch256PrivateKeys: batch256PrivateKeys,
                batch1024PrivateKeys: batch1024PrivateKeys,
                ecdsaMessage: ecdsaMessage,
                schnorrDigest: schnorrDigest,
                compressedPublicKey: compressedPublicKey,
                verificationKey: verificationKey,
                ecdsaSignature: ecdsaSignature,
                schnorrSignature: schnorrSignature,
                mnemonic: mnemonic,
                mnemonicPhrase: mnemonic.phrase,
                basePayload: basePayload,
                base58EncodedPayload: base58EncodedPayload,
                base32EncodedPayload: base32EncodedPayload,
                rootExtendedPrivateKey: rootExtendedPrivateKey,
                rootExtendedPublicKey: rootExtendedPublicKey,
                genericPointMultiplicationScalar: genericPointMultiplicationScalar,
                jointGeneratorScalar: jointGeneratorScalar,
                jointVerificationKeyScalar: jointVerificationKeyScalar
            )
        }

        private static func makePrivateKey(index: Int) -> Data {
            var privateKey = Data(repeating: 0x00, count: 32)
            let resolvedIndex = UInt32(index)
            privateKey[28] = UInt8((resolvedIndex >> 24) & 0xff)
            privateKey[29] = UInt8((resolvedIndex >> 16) & 0xff)
            privateKey[30] = UInt8((resolvedIndex >> 8) & 0xff)
            privateKey[31] = UInt8(resolvedIndex & 0xff)
            return privateKey
        }
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
        let totalText = String(format: "%.3f", totalMilliseconds)
        let averageText = String(format: "%.3f", averageMicroseconds)
        print("\(name): total \(totalText) ms, avg \(averageText) us")
    }
}
