// OpalCryptoBenchmarks~PublicKeyBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func runPublicKeyBenchmarks(context: BenchmarkContext) async throws -> Int {
        var checksum = 0

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

        return checksum
    }
}
