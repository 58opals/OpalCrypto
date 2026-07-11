// OpalCryptoBenchmarks~SignatureBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func signatureBenchmarks() -> [BenchmarkCase] {
        [
            BenchmarkCase(
                name: "ECDSA sign",
                iterations: 200,
                suites: [.hot],
                operation: .sync { context in
                    let signature = try OpalCrypto.Signature.ECDSA.sign(
                        message: context.ecdsaMessage,
                        privateKey: context.singlePrivateKey,
                        format: .der
                    )
                    return signature.rawRepresentation.count ^ Int(signature.rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "ECDSA verify",
                iterations: 200,
                suites: [.hot],
                operation: .sync { context in
                    let isValid = try context.ecdsaSignature.verify(
                        message: context.ecdsaMessage,
                        publicKey: context.compressedPublicKey
                    )
                    return isValid ? 1 : 0
                }
            ),
            BenchmarkCase(
                name: "ECDSA verify (cached key)",
                iterations: 200,
                suites: [.smoke, .hot],
                operation: .sync { context in
                    let isValid = try context.ecdsaSignature.verify(
                        message: context.ecdsaMessage,
                        verificationKey: context.verificationKey
                    )
                    return isValid ? 1 : 0
                }
            ),
            BenchmarkCase(
                name: "Batch ECDSA verify digest (cached key, 256)",
                iterations: 3,
                suites: [.hot],
                operation: .sync { context in
                    verificationChecksum(
                        try ecdsaDigestBatchResults(context: context, count: 256)
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal probe ECDSA verify digest (cached key, 256)",
                iterations: 3,
                suites: [.hot],
                operation: .sync { context in
                    try MetalVerificationProbe.run(
                        expectedResults: ecdsaDigestBatchResults(context: context, count: 256),
                        seed: 0xec_d5_a2_56
                    )
                }
            ),
            BenchmarkCase(
                name: "Batch ECDSA verify digest (cached key, 1024)",
                iterations: 1,
                suites: [.hot],
                operation: .sync { context in
                    verificationChecksum(
                        try ecdsaDigestBatchResults(context: context, count: 1024)
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal probe ECDSA verify digest (cached key, 1024)",
                iterations: 1,
                suites: [.hot],
                operation: .sync { context in
                    try MetalVerificationProbe.run(
                        expectedResults: ecdsaDigestBatchResults(context: context, count: 1024),
                        seed: 0xec_d5_a2_24
                    )
                }
            ),
            BenchmarkCase(
                name: "Schnorr sign",
                iterations: 200,
                suites: [.hot],
                operation: .sync { context in
                    let signature = try OpalCrypto.Signature.Schnorr.sign(
                        digest: context.schnorrDigest,
                        privateKey: context.singlePrivateKey,
                        noncePolicy: .bip340Deterministic
                    )
                    return signature.rawRepresentation.count ^ Int(signature.rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Schnorr verify",
                iterations: 200,
                suites: [.hot],
                operation: .sync { context in
                    let isValid = try context.schnorrSignature.verify(
                        digest: context.schnorrDigest,
                        publicKey: context.compressedPublicKey
                    )
                    return isValid ? 1 : 0
                }
            ),
            BenchmarkCase(
                name: "Schnorr verify (cached key)",
                iterations: 200,
                suites: [.smoke, .hot],
                operation: .sync { context in
                    let isValid = try context.schnorrSignature.verify(
                        digest: context.schnorrDigest,
                        verificationKey: context.verificationKey
                    )
                    return isValid ? 1 : 0
                }
            ),
            BenchmarkCase(
                name: "Batch Schnorr verify (cached key, 256)",
                iterations: 3,
                suites: [.hot, .metal],
                operation: .sync { context in
                    verificationChecksum(
                        try schnorrBatchResults(context: context, count: 256)
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal Schnorr verify core (cached key, 256)",
                iterations: 1,
                suites: [.hot, .metal],
                operation: .sync { context in
                    try MetalSchnorrVerificationCore.run(
                        input: context.metalSchnorrVerificationInput,
                        count: 256
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal probe Schnorr verify (cached key, 256)",
                iterations: 3,
                suites: [.hot],
                operation: .sync { context in
                    try MetalVerificationProbe.run(
                        expectedResults: schnorrBatchResults(context: context, count: 256),
                        seed: 0x5c_40_22_56
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal Schnorr verify core (cached key, 1024)",
                iterations: 1,
                suites: [.hot, .metal],
                operation: .sync { context in
                    try MetalSchnorrVerificationCore.run(
                        input: context.metalSchnorrVerificationInput,
                        count: 1024
                    )
                }
            ),
            BenchmarkCase(
                name: "Batch Schnorr verify (cached key, 1024)",
                iterations: 1,
                suites: [.hot, .metal],
                operation: .sync { context in
                    verificationChecksum(
                        try schnorrBatchResults(context: context, count: 1024)
                    )
                }
            ),
            BenchmarkCase(
                name: "Metal probe Schnorr verify (cached key, 1024)",
                iterations: 1,
                suites: [.hot],
                operation: .sync { context in
                    try MetalVerificationProbe.run(
                        expectedResults: schnorrBatchResults(context: context, count: 1024),
                        seed: 0x5c_40_22_24
                    )
                }
            )
        ] + schnorrDistinctVerificationBenchmarkCases()
            + schnorrVaryingKeyVerificationBenchmarkCases()
            + schnorrProductionAPIBenchmarkCases()
    }
}
