// OpalCrypto.Key.Mnemonic~SeedDerivation.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Key.Mnemonic {
    /// Derives a BIP-39 seed from this mnemonic and optional passphrase.
    ///
    /// The mnemonic phrase, passphrase, and returned seed are secret-bearing. Diagnostics record only public-safe metadata such as word count, language, passphrase byte count, and output byte count.
    public func deriveSeed(passphrase: String = "") throws -> OpalCrypto.Key.Seed {
        let fields = seedDeriveFields(passphrase: passphrase)
        do {
            let seed = try OpalCrypto.Key.Seed(
                rawRepresentation: MnemonicCodecModel.deriveSeed(
                    phrase: phrase,
                    passphrase: passphrase
                )
            )
            Self.recordSeedDeriveSucceeded(seed: seed, fields: fields)
            return seed
        } catch {
            Self.recordSeedDeriveFailed(error, fields: fields)
            throw error
        }
    }

    private func seedDeriveFields(passphrase: String) -> [OpalDiagnostics.Field] {
        [
            OpalDiagnostics.Field.operationField("mnemonic_seed_derive"),
            OpalDiagnostics.Field.formatField("bip39"),
            OpalDiagnostics.Field.publicField("word_count", words.count),
            OpalDiagnostics.Field.publicField("language", language.rawValue),
            OpalDiagnostics.Field.publicField("passphrase_byte_count", passphrase.utf8.count)
        ]
    }

    private static func recordSeedDeriveSucceeded(
        seed: OpalCrypto.Key.Seed,
        fields: [OpalDiagnostics.Field]
    ) {
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
            event: OpalDiagnostics.Event.mnemonicSeedDeriveSucceeded,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicSeedDeriveSucceeded),
            fields: fields + [
                OpalDiagnostics.Field.outputLengthField(seed.rawRepresentation.count)
            ]
        )
    }

    private static func recordSeedDeriveFailed(
        _ error: Swift.Error,
        fields: [OpalDiagnostics.Field]
    ) {
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.key).record(
            event: OpalDiagnostics.Event.mnemonicSeedDeriveFailed,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.mnemonicSeedDeriveFailed),
            fields: fields + OpalDiagnostics.Field.errorFields(error)
        )
    }
}
