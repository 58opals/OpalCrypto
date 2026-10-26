// OpalCryptoBenchmarks~RSABSSABenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    // The first unmeasured warmup acquires this process-local attempt key.
    // Every operation still creates a fresh randomized request.
    private static let rsabssaBenchmarkSigningKeyResult:
        Result<OpalCrypto.RSABSSA.SigningKey, Swift.Error> = Result {
            try OpalCrypto.RSABSSA.SigningKey.generate()
        }
    private static let rsabssaBenchmarkMessage = Data(
        "opalcrypto-benchmark-rsabssa".utf8
    )

    private enum RSABSSABenchmarkError: Swift.Error {
        case invalidRequestShape
        case signatureVerificationFailed
    }

    static func rsabssaBenchmarks() -> [BenchmarkCase] {
        [
            BenchmarkCase(
                name: "RSABSSA makeBlindRequest (RSA-2048)",
                iterations: 32,
                suites: [.hot],
                operation: .sync { _ in
                    let signingKey = try rsabssaBenchmarkSigningKeyResult.get()
                    let request = try OpalCrypto.RSABSSA.makeBlindRequest(
                        message: rsabssaBenchmarkMessage,
                        using: signingKey.verificationKey
                    )
                    let variant = OpalCrypto.RSABSSA.Variant
                        .sha384PSSRandomized
                    guard request.blindedMessage.rawRepresentation.count
                            == variant.modulusByteCount,
                          request.messageRandomizer.rawRepresentation.count
                            == variant.messageRandomizerByteCount,
                          request.recoveryState.rawRepresentation.count
                            == OpalCrypto.RSABSSA.BlindRequest.RecoveryState
                                .rawRepresentationByteCount else {
                        throw RSABSSABenchmarkError.invalidRequestShape
                    }
                    return request.blindedMessage.rawRepresentation.count
                        ^ request.messageRandomizer.rawRepresentation.count
                }
            ),
            BenchmarkCase(
                name: "RSABSSA blind-signing round trip (RSA-2048)",
                iterations: 32,
                suites: [.hot],
                operation: .sync { _ in
                    let signingKey = try rsabssaBenchmarkSigningKeyResult.get()
                    let request = try OpalCrypto.RSABSSA.makeBlindRequest(
                        message: rsabssaBenchmarkMessage,
                        using: signingKey.verificationKey
                    )
                    let blindSignature = try signingKey.blindSign(
                        request.blindedMessage
                    )
                    let signature = try request.finalize(
                        blindSignature,
                        using: signingKey.verificationKey
                    )
                    guard signature.verify(
                        message: rsabssaBenchmarkMessage,
                        messageRandomizer: request.messageRandomizer,
                        using: signingKey.verificationKey
                    ) else {
                        throw RSABSSABenchmarkError.signatureVerificationFailed
                    }
                    return signature.rawRepresentation.count
                }
            )
        ]
    }
}
