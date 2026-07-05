// OpalCryptoBenchmarks~PublicKeyBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func publicKeyBenchmarks() -> [BenchmarkCase] {
        [
            BenchmarkCase(
                name: "Single compressed public-key derivation",
                iterations: 400,
                suites: [.smoke, .hot],
                operation: .sync { context in
                    let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(
                        from: context.singlePrivateKey
                    )
                    return publicKey.rawRepresentation.count
                        ^ Int(publicKey.rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Batch compressed public-key derivation (64)",
                iterations: 20,
                suites: [.hot],
                operation: .asynchronous { context in
                    let publicKeys = try await OpalCrypto.Secp256k1.derivePublicKeys(
                        from: context.batch64PrivateKeys
                    )
                    return publicKeys.count ^ Int(publicKeys[0].rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Batch compressed public-key derivation (256)",
                iterations: 8,
                suites: [.hot],
                operation: .asynchronous { context in
                    let publicKeys = try await OpalCrypto.Secp256k1.derivePublicKeys(
                        from: context.batch256PrivateKeys
                    )
                    return publicKeys.count ^ Int(publicKeys[0].rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Batch compressed public-key derivation (256, forced serial)",
                iterations: 8,
                suites: [.hot],
                operation: .asynchronous { context in
                    let publicKeys = try await PerformanceBenchmarkOperations
                        .deriveCompressedPublicKeysSerial(from: context.batch256PrivateKeyData)
                    return publicKeys.count ^ Int(publicKeys[0][0])
                }
            ),
            BenchmarkCase(
                name: "Batch compressed public-key derivation (256, forced parallel)",
                iterations: 8,
                suites: [.hot],
                operation: .asynchronous { context in
                    let publicKeys = try await PerformanceBenchmarkOperations
                        .deriveCompressedPublicKeysParallel(from: context.batch256PrivateKeyData)
                    return publicKeys.count ^ Int(publicKeys[0][0])
                }
            ),
            BenchmarkCase(
                name: "Batch compressed public-key derivation from scalars (256)",
                iterations: 8,
                suites: [.hot],
                operation: .asynchronous { context in
                    let publicKeys = try await PerformanceBenchmarkOperations
                        .deriveCompressedPublicKeysFromScalars(from: context.batch256PrivateKeyData)
                    return publicKeys.count ^ Int(publicKeys[0][0])
                }
            ),
            BenchmarkCase(
                name: "Batch compressed public-key derivation (1024)",
                iterations: 3,
                suites: [.hot],
                operation: .asynchronous { context in
                    let publicKeys = try await OpalCrypto.Secp256k1.derivePublicKeys(
                        from: context.batch1024PrivateKeys
                    )
                    return publicKeys.count ^ Int(publicKeys[0].rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Batch compressed public-key derivation (1024, forced serial)",
                iterations: 3,
                suites: [.hot],
                operation: .asynchronous { context in
                    let publicKeys = try await PerformanceBenchmarkOperations
                        .deriveCompressedPublicKeysSerial(from: context.batch1024PrivateKeyData)
                    return publicKeys.count ^ Int(publicKeys[0][0])
                }
            ),
            BenchmarkCase(
                name: "Batch compressed public-key derivation (1024, forced parallel)",
                iterations: 3,
                suites: [.hot],
                operation: .asynchronous { context in
                    let publicKeys = try await PerformanceBenchmarkOperations
                        .deriveCompressedPublicKeysParallel(from: context.batch1024PrivateKeyData)
                    return publicKeys.count ^ Int(publicKeys[0][0])
                }
            ),
            BenchmarkCase(
                name: "Batch compressed public-key derivation from scalars (1024)",
                iterations: 3,
                suites: [.hot],
                operation: .asynchronous { context in
                    let publicKeys = try await PerformanceBenchmarkOperations
                        .deriveCompressedPublicKeysFromScalars(from: context.batch1024PrivateKeyData)
                    return publicKeys.count ^ Int(publicKeys[0][0])
                }
            ),
            BenchmarkCase(
                name: "Batch Jacobian multiplication (256)",
                iterations: 8,
                suites: [.hot],
                operation: .sync { context in
                    try PerformanceBenchmarkOperations.multiplyBatchGeneratorScalars(
                        from: context.batch256PrivateKeyData
                    )
                }
            ),
            BenchmarkCase(
                name: "Batch affine conversion (256)",
                iterations: 8,
                suites: [.hot],
                operation: .sync { context in
                    let publicKeys = try PerformanceBenchmarkOperations
                        .convertBatchJacobianPointBufferToCompressedPublicKeys(
                            context.batch256JacobianPointBuffer
                        )
                    return publicKeys.count ^ Int(publicKeys[0][0])
                }
            ),
            BenchmarkCase(
                name: "Batch Jacobian multiplication (1024)",
                iterations: 3,
                suites: [.hot],
                operation: .sync { context in
                    try PerformanceBenchmarkOperations.multiplyBatchGeneratorScalars(
                        from: context.batch1024PrivateKeyData
                    )
                }
            ),
            BenchmarkCase(
                name: "Batch affine conversion (1024)",
                iterations: 3,
                suites: [.hot],
                operation: .sync { context in
                    let publicKeys = try PerformanceBenchmarkOperations
                        .convertBatchJacobianPointBufferToCompressedPublicKeys(
                            context.batch1024JacobianPointBuffer
                        )
                    return publicKeys.count ^ Int(publicKeys[0][0])
                }
            ),
            BenchmarkCase(
                name: "Verification-key construction",
                iterations: 400,
                suites: [.hot],
                operation: .sync { context in
                    let verificationKey = OpalCrypto.Signature.VerificationKey(
                        publicKey: context.compressedPublicKey
                    )
                    return verificationKey.publicKey.rawRepresentation.count
                        ^ Int(verificationKey.publicKey.rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Parsed public-key construction",
                iterations: 400,
                suites: [.hot],
                operation: .sync { context in
                    let parsedPublicKey = try PerformanceBenchmarkOperations.constructParsedPublicKey(
                        publicKey: context.compressedPublicKey.rawRepresentation
                    )
                    return parsedPublicKey.count ^ Int(parsedPublicKey[0])
                }
            ),
            BenchmarkCase(
                name: "Parsed private-key construction",
                iterations: 400,
                suites: [.hot],
                operation: .sync { context in
                    let parsedPrivateKey = try PerformanceBenchmarkOperations.constructParsedPrivateKey(
                        privateKey: context.singlePrivateKeyData
                    )
                    return parsedPrivateKey.count ^ Int(parsedPrivateKey[0])
                }
            ),
            BenchmarkCase(
                name: "Field sqrt",
                iterations: 400,
                suites: [.hot],
                operation: .sync { context in
                    let squareRoot = try PerformanceBenchmarkOperations.computeFieldSquareRoot(
                        fieldElementData32Bytes: context.fieldSquareRootInput
                    )
                    return squareRoot.count ^ Int(squareRoot[31])
                }
            ),
            BenchmarkCase(
                name: "Field quadratic-residue check",
                iterations: 400,
                suites: [.hot],
                operation: .sync { context in
                    try PerformanceBenchmarkOperations.checkFieldQuadraticResidue(
                        fieldElementData32Bytes: context.fieldSquareRootInput
                    ) ? 1 : 0
                }
            ),
            BenchmarkCase(
                name: "Scalar inversion",
                iterations: 400,
                suites: [.hot],
                operation: .sync { context in
                    let inverse = try PerformanceBenchmarkOperations.invertScalar(
                        scalarData32Bytes: context.scalarInversionInput
                    )
                    return inverse.count ^ Int(inverse[0])
                }
            ),
            BenchmarkCase(
                name: "Generic point multiplication",
                iterations: 200,
                suites: [.hot],
                operation: .sync { context in
                    let multipliedPublicKey = try PerformanceBenchmarkOperations
                        .multiplyVerificationKey(
                            scalarData32Bytes: context.genericPointMultiplicationScalar,
                            verificationKey: context.verificationKey
                        )
                    return multipliedPublicKey.count ^ Int(multipliedPublicKey.first ?? 0)
                }
            ),
            BenchmarkCase(
                name: "Joint multiplication",
                iterations: 200,
                suites: [.hot],
                operation: .sync { context in
                    let multipliedPublicKey = try PerformanceBenchmarkOperations
                        .jointMultiplyGeneratorAndVerificationKey(
                            generatorScalarData32Bytes: context.jointGeneratorScalar,
                            verificationKeyScalarData32Bytes: context.jointVerificationKeyScalar,
                            verificationKey: context.verificationKey
                        )
                    return multipliedPublicKey.count ^ Int(multipliedPublicKey.first ?? 0)
                }
            )
        ]
    }
}
