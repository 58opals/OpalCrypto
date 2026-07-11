// OpalCryptoBenchmarks~PublicKeyPrimitiveBenchmarks.swift

import OpalCrypto

extension OpalCryptoBenchmarks {
    static func publicKeyPrimitiveBenchmarkCases() -> [BenchmarkCase] {
        [
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
                    guard let squareRoot = try PerformanceBenchmarkOperations
                        .computeFieldSquareRoot(
                            fieldElementData32Bytes: context.fieldSquareRootInput
                        ) else {
                        return 0
                    }
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
