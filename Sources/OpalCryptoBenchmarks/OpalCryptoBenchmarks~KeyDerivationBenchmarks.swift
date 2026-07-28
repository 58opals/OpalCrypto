// OpalCryptoBenchmarks~KeyDerivationBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func keyDerivationBenchmarks() -> [BenchmarkCase] {
        [
            BenchmarkCase(
                name: "PBKDF2",
                iterations: 60,
                suites: [.smoke],
                operation: .sync { context in
                    let derivedKey = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                        password: context.basePayload,
                        salt: try OpalCrypto.KeyDerivation.Salt(
                            rawRepresentation: context.batch64PrivateKeyData[0]
                        ),
                        iterationCount: 2048,
                        derivedKeyLength: 64,
                        maximumWorkUnitCount: 2048
                    )
                    return derivedKey.rawRepresentation.count ^ Int(derivedKey.rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Mnemonic parse",
                iterations: 200,
                suites: [],
                operation: .sync { context in
                    let mnemonic = try OpalCrypto.Key.Mnemonic(
                        phrase: context.mnemonicPhrase,
                        language: .english
                    )
                    return mnemonic.words.count ^ mnemonic.phrase.count
                }
            ),
            BenchmarkCase(
                name: "Mnemonic generate",
                iterations: 60,
                suites: [],
                operation: .sync { _ in
                    let mnemonic = try OpalCrypto.Key.Mnemonic.generate(
                        length: .words24,
                        language: .english
                    )
                    return mnemonic.words.count ^ mnemonic.phrase.count
                }
            ),
            BenchmarkCase(
                name: "Mnemonic seed derivation",
                iterations: 80,
                suites: [],
                operation: .sync { context in
                    let seed = try context.mnemonic.deriveSeed(passphrase: "benchmark")
                    return seed.rawRepresentation.count ^ Int(seed.rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Extended-key derivation",
                iterations: 120,
                suites: [],
                operation: .sync { context in
                    let child = try context.rootExtendedPrivate.derived(
                        indices: [0x8000_0000, 1, 2, 3]
                    )
                    return Int(child.depth) ^ Int(child.privateKey.rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Extended private-key derivation (single hop)",
                iterations: 200,
                suites: [],
                operation: .sync { context in
                    let child = try context.rootExtendedPrivate.derived(indices: [1])
                    return Int(child.depth) ^ Int(child.privateKey.rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Extended public-key derivation (single hop)",
                iterations: 200,
                suites: [],
                operation: .sync { context in
                    let child = try context.rootExtendedPublic.derived(indices: [1])
                    return Int(child.depth) ^ Int(child.publicKey.rawRepresentation[0])
                }
            ),
            BenchmarkCase(
                name: "Extended public-key derivation (repeated)",
                iterations: 120,
                suites: [],
                operation: .sync { context in
                    let child = try context.rootExtendedPublic.derived(indices: [1, 2, 3, 4])
                    return Int(child.depth) ^ Int(child.publicKey.rawRepresentation[0])
                }
            )
        ]
    }
}
