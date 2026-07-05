// OpalCryptoBenchmarks~SharedSecretBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func sharedSecretBenchmarks() -> [BenchmarkCase] {
        [
            BenchmarkCase(
                name: "Batch shared-secret derivation (64)",
                iterations: 20,
                suites: [.hot],
                operation: .asynchronous { context in
                    try await sharedSecretChecksum(
                        privateKey: context.singlePrivateKey,
                        publicKeys: context.batch64PublicKeys
                    )
                }
            ),
            BenchmarkCase(
                name: "Batch shared-secret derivation (256)",
                iterations: 8,
                suites: [.hot],
                operation: .asynchronous { context in
                    try await sharedSecretChecksum(
                        privateKey: context.singlePrivateKey,
                        publicKeys: context.batch256PublicKeys
                    )
                }
            ),
            BenchmarkCase(
                name: "Batch shared-secret derivation (256, forced serial)",
                iterations: 8,
                suites: [.hot],
                operation: .asynchronous { context in
                    let sharedSecrets = try await PerformanceBenchmarkOperations
                        .deriveSharedSecretsSerial(
                            privateKey: context.singlePrivateKeyData,
                            publicKeys: context.batch256PublicKeyData
                        )
                    return dataChecksum(sharedSecrets)
                }
            ),
            BenchmarkCase(
                name: "Batch shared-secret derivation (256, forced parallel)",
                iterations: 8,
                suites: [.hot],
                operation: .asynchronous { context in
                    let sharedSecrets = try await PerformanceBenchmarkOperations
                        .deriveSharedSecretsParallel(
                            privateKey: context.singlePrivateKeyData,
                            publicKeys: context.batch256PublicKeyData
                        )
                    return dataChecksum(sharedSecrets)
                }
            ),
            BenchmarkCase(
                name: "Batch shared-secret derivation (1024)",
                iterations: 3,
                suites: [.hot],
                operation: .asynchronous { context in
                    try await sharedSecretChecksum(
                        privateKey: context.singlePrivateKey,
                        publicKeys: context.batch1024PublicKeys
                    )
                }
            ),
            BenchmarkCase(
                name: "Batch shared-secret derivation (1024, forced serial)",
                iterations: 3,
                suites: [.hot],
                operation: .asynchronous { context in
                    let sharedSecrets = try await PerformanceBenchmarkOperations
                        .deriveSharedSecretsSerial(
                            privateKey: context.singlePrivateKeyData,
                            publicKeys: context.batch1024PublicKeyData
                        )
                    return dataChecksum(sharedSecrets)
                }
            ),
            BenchmarkCase(
                name: "Batch shared-secret derivation (1024, forced parallel)",
                iterations: 3,
                suites: [.hot],
                operation: .asynchronous { context in
                    let sharedSecrets = try await PerformanceBenchmarkOperations
                        .deriveSharedSecretsParallel(
                            privateKey: context.singlePrivateKeyData,
                            publicKeys: context.batch1024PublicKeyData
                        )
                    return dataChecksum(sharedSecrets)
                }
            ),
            BenchmarkCase(
                name: "Receiver scan shared-secret fingerprint core (1024)",
                iterations: 3,
                suites: [.hot],
                operation: .asynchronous { context in
                    let sharedSecrets = try await OpalCrypto.Secp256k1.deriveSharedSecrets(
                        privateKey: context.singlePrivateKey,
                        publicKeys: context.batch1024PublicKeys
                    )
                    let fingerprints = sharedSecrets.map {
                        OpalCrypto.Hashing.hash160($0.rawRepresentation)
                    }
                    return dataChecksum(fingerprints)
                }
            )
        ]
    }

    private static func sharedSecretChecksum(
        privateKey: OpalCrypto.Secp256k1.PrivateKey,
        publicKeys: [OpalCrypto.Secp256k1.PublicKey]
    ) async throws -> Int {
        let sharedSecrets = try await OpalCrypto.Secp256k1.deriveSharedSecrets(
            privateKey: privateKey,
            publicKeys: publicKeys
        )
        return dataChecksum(sharedSecrets.map(\.rawRepresentation))
    }

    private static func dataChecksum(_ values: [Data]) -> Int {
        var checksum = values.count
        for value in values {
            checksum ^= value.count
            if let firstByte = value.first {
                checksum ^= Int(firstByte)
            }
            if let lastByte = value.last {
                checksum ^= Int(lastByte)
            }
        }
        return checksum
    }
}
