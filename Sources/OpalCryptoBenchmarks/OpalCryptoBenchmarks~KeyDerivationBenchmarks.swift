// OpalCryptoBenchmarks~KeyDerivationBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func runKeyDerivationBenchmarks(context: BenchmarkContext) throws -> Int {
        var checksum = 0

        checksum ^= try runSyncBenchmark(name: "PBKDF2", iterations: 60) {
            let derivedKey = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                password: context.basePayload,
                salt: try OpalCrypto.KeyDerivation.Salt(
                    rawRepresentation: context.batch64PrivateKeyData[0]
                ),
                iterationCount: 2048,
                derivedKeyLength: 64
            )
            return derivedKey.rawRepresentation.count ^ Int(derivedKey.rawRepresentation[0])
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
            return seed.rawRepresentation.count ^ Int(seed.rawRepresentation[0])
        }

        checksum ^= try runSyncBenchmark(name: "Extended-key derivation", iterations: 120) {
            let child = try context.rootExtendedPrivate.derived(
                indices: [0x8000_0000, 1, 2, 3]
            )
            return Int(child.depth) ^ Int(child.privateKey.rawRepresentation[0])
        }

        checksum ^= try runSyncBenchmark(
            name: "Extended private-key derivation (single hop)",
            iterations: 200
        ) {
            let child = try context.rootExtendedPrivate.derived(indices: [1])
            return Int(child.depth) ^ Int(child.privateKey.rawRepresentation[0])
        }

        checksum ^= try runSyncBenchmark(
            name: "Extended public-key derivation (single hop)",
            iterations: 200
        ) {
            let child = try context.rootExtendedPublic.derived(indices: [1])
            return Int(child.depth) ^ Int(child.publicKey.rawRepresentation[0])
        }

        checksum ^= try runSyncBenchmark(
            name: "Extended public-key derivation (repeated)",
            iterations: 120
        ) {
            let child = try context.rootExtendedPublic.derived(indices: [1, 2, 3, 4])
            return Int(child.depth) ^ Int(child.publicKey.rawRepresentation[0])
        }

        return checksum
    }
}
