// DiagnosticsIntegrationValidator~SecretMaterial.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("Secret-bearing diagnostics omit raw secret material")
    func validateSecretBearingDiagnosticsOmitRawSecretMaterial() throws {
        try withDiagnosticsCapture {
            let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            let passphrase = "wallet-passphrase-secret"
            let mnemonic = try OpalCrypto.Key.Mnemonic(phrase: phrase, language: .english)
            let seed = try mnemonic.deriveSeed(passphrase: passphrase)
            let extendedPrivateKey = try OpalCrypto.Key.ExtendedPrivate.root(seed: seed)
            let extendedPrivateKeyText = extendedPrivateKey.serialize()
            _ = try OpalCrypto.Key.ExtendedPrivate(extendedPrivateKeyText)
            let privateKey = try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: Data([0x03]) + Data(repeating: 0xA5, count: 31)
            )
            let walletImportFormatText = OpalCrypto.Key.WIF(privateKey: privateKey).serialize()
            _ = try OpalCrypto.Key.WIF(walletImportFormatText)
            let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            let sharedSecret = try OpalCrypto.Secp256k1.deriveSharedSecret(
                privateKey: privateKey,
                publicKey: publicKey
            )
            let sharedPointX =
                OpalCrypto.Secp256k1.deriveSharedPointXCoordinate(
                    signingKey: privateKey.makeSigningKey(),
                    publicKey: publicKey
                )
            _ = try OpalCrypto.Secp256k1.SharedSecret(
                rawRepresentation: sharedSecret.rawRepresentation
            )
            let symmetricKey = try OpalCrypto.Communication.SymmetricKey(
                rawRepresentation: Data(repeating: 0x42, count: 32)
            )
            let derivedKey = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                password: Data(passphrase.utf8),
                salt: try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("public-salt".utf8)),
                iterationCount: 1,
                derivedKeyLength: 32,
                maximumWorkUnitCount: 1
            )

            let forbiddenValues = [
                phrase,
                "abandon",
                passphrase,
                hex(seed.rawRepresentation),
                extendedPrivateKeyText,
                walletImportFormatText,
                hex(privateKey.rawRepresentation),
                hex(sharedSecret.rawRepresentation),
                hex(sharedPointX.rawRepresentation),
                hex(symmetricKey.rawRepresentation),
                hex(derivedKey.rawRepresentation)
            ]
            let forbiddenFieldNames = [
                "mnemonic",
                "phrase",
                "passphrase",
                "seed",
                "private_key",
                "wif",
                "shared_secret",
                "shared_point_x",
                "symmetric_key",
                "password",
                "derived_key"
            ]

            for record in OpalDiagnostics.recentRecords {
                for fieldName in forbiddenFieldNames {
                    #expect(
                        field(fieldName, in: record) == nil,
                        "\(record.event.rawValue) exposed forbidden field \(fieldName)."
                    )
                }
                for value in forbiddenValues {
                    #expect(
                        record.fields.contains { $0.value.contains(value) } == false,
                        "\(record.event.rawValue) exposed secret value \(value)."
                    )
                }
            }
        }
    }
}
