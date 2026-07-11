// SecretMaterialDescriptionValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Secret material description validation")
struct SecretMaterialDescriptionValidator {
    @Test("Secret-bearing public values use redacted string descriptions")
    func secretBearingPublicValuesUseRedactedStringDescriptions() throws {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let passphrase = "wallet-passphrase-secret"
        let mnemonic = try OpalCrypto.Key.Mnemonic(phrase: phrase, language: .english)
        let seed = try mnemonic.deriveSeed(passphrase: passphrase)
        let extendedPrivateKey = try OpalCrypto.Key.ExtendedPrivate.root(seed: seed)
        let extendedPrivateKeyText = extendedPrivateKey.serialize()
        let privateKey = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: Data([0x03]) + Data(repeating: 0xA5, count: 31)
        )
        let signingKey = privateKey.makeSigningKey()
        let walletImportFormat = OpalCrypto.Key.WIF(privateKey: privateKey)
        let walletImportFormatText = walletImportFormat.serialize()
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let sharedSecret = try OpalCrypto.Secp256k1.deriveSharedSecret(
            privateKey: privateKey,
            publicKey: publicKey
        )
        let symmetricKey = try OpalCrypto.Communication.SymmetricKey(
            rawRepresentation: Data(repeating: 0x42, count: 32)
        )
        let derivedKey = try OpalCrypto.KeyDerivation.DerivedKey(
            rawRepresentation: Data("derived-key-secret-material".utf8)
        )

        let cases = [
            DescriptionCase(
                label: "mnemonic",
                describing: String(describing: mnemonic),
                reflecting: String(reflecting: mnemonic),
                forbiddenFragments: [phrase, "abandon", passphrase, "words", "phrase"]
            ),
            DescriptionCase(
                label: "seed",
                describing: String(describing: seed),
                reflecting: String(reflecting: seed),
                forbiddenFragments: [hex(seed.rawRepresentation), "rawRepresentation"]
            ),
            DescriptionCase(
                label: "extendedPrivate",
                describing: String(describing: extendedPrivateKey),
                reflecting: String(reflecting: extendedPrivateKey),
                forbiddenFragments: [extendedPrivateKeyText, "payload", "parsedPrivateKeyModel", "chainCode"]
            ),
            DescriptionCase(
                label: "privateKey",
                describing: String(describing: privateKey),
                reflecting: String(reflecting: privateKey),
                forbiddenFragments: [hex(privateKey.rawRepresentation), "rawRepresentation"]
            ),
            DescriptionCase(
                label: "signingKey",
                describing: String(describing: signingKey),
                reflecting: String(reflecting: signingKey),
                forbiddenFragments: [
                    hex(privateKey.rawRepresentation),
                    "rawRepresentation",
                    "parsedPrivateKeyModel",
                    "scalar"
                ]
            ),
            DescriptionCase(
                label: "wif",
                describing: String(describing: walletImportFormat),
                reflecting: String(reflecting: walletImportFormat),
                forbiddenFragments: [walletImportFormatText, hex(privateKey.rawRepresentation), "rawRepresentation"]
            ),
            DescriptionCase(
                label: "sharedSecret",
                describing: String(describing: sharedSecret),
                reflecting: String(reflecting: sharedSecret),
                forbiddenFragments: [hex(sharedSecret.rawRepresentation), "rawRepresentation"]
            ),
            DescriptionCase(
                label: "symmetricKey",
                describing: String(describing: symmetricKey),
                reflecting: String(reflecting: symmetricKey),
                forbiddenFragments: [hex(symmetricKey.rawRepresentation), "rawRepresentation"]
            ),
            DescriptionCase(
                label: "derivedKey",
                describing: String(describing: derivedKey),
                reflecting: String(reflecting: derivedKey),
                forbiddenFragments: ["derived-key-secret-material", "rawRepresentation"]
            )
        ]

        for testCase in cases {
            #expect(
                testCase.describing.contains("redacted"),
                "\(testCase.label) description should declare redaction."
            )
            #expect(
                testCase.reflecting.contains("redacted"),
                "\(testCase.label) debug description should declare redaction."
            )
            for fragment in testCase.forbiddenFragments {
                #expect(
                    testCase.describing.contains(fragment) == false,
                    "\(testCase.label) description exposed \(fragment)."
                )
                #expect(
                    testCase.reflecting.contains(fragment) == false,
                    "\(testCase.label) debug description exposed \(fragment)."
                )
            }
        }
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
