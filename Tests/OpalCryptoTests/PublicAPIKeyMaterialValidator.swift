// PublicAPIKeyMaterialValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API key material validation")
struct PublicAPIKeyMaterialValidator {
    @Test("Round-trip mainnet wallet import format and reject invalid variants")
    func roundTripMainnetWalletImportFormatAndRejectInvalidVariants() throws {
        let privateKey = try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: Data(privateKeyBytes))

        let compressedWalletImportFormat = OpalCrypto.Key.WIF(privateKey: privateKey, isCompressed: true)
        #expect(try compressedWalletImportFormat.serialize() == compressedWalletImportFormatString)
        #expect(try OpalCrypto.Key.WIF(compressedWalletImportFormatString) == compressedWalletImportFormat)

        let uncompressedWalletImportFormat = OpalCrypto.Key.WIF(privateKey: privateKey, isCompressed: false)
        #expect(try uncompressedWalletImportFormat.serialize() == uncompressedWalletImportFormatString)
        #expect(try OpalCrypto.Key.WIF(uncompressedWalletImportFormatString) == uncompressedWalletImportFormat)

        do {
            _ = try OpalCrypto.Key.WIF(invalidChecksumWalletImportFormatString)
            Issue.record("Expected invalid checksum error.")
        } catch let error as OpalCrypto.Key.WIF.Error {
            #expect(error == .invalidChecksum)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Key.WIF(testnetWalletImportFormatString)
            Issue.record("Expected invalid version error.")
        } catch let error as OpalCrypto.Key.WIF.Error {
            #expect(error == .invalidVersion(actual: 0xef))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject truncated wallet import payloads with the real payload length")
    func rejectTruncatedWalletImportPayloadsWithTheRealPayloadLength() throws {
        let truncatedPayload = Data([0x80] + Array(repeating: UInt8(0x01), count: 31))
        let serialized = Base58CheckCodecModel.encode(payload: truncatedPayload)

        do {
            _ = try OpalCrypto.Key.WIF(serialized)
            Issue.record("Expected invalid payload length error.")
        } catch let error as OpalCrypto.Key.WIF.Error {
            #expect(error == .invalidPayloadLength(actual: 32))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Round-trip extended keys and derive raw child indices")
    func roundTripExtendedKeysAndDeriveRawChildIndices() throws {
        let rootKey = try OpalCrypto.Key.ExtendedPrivate.root(
            seed: OpalCrypto.Key.Seed(rawRepresentation: Data(hexadecimal: seedHex))
        )
        #expect(rootKey.serialize() == rootPrivateKeyString)
        #expect(rootKey.publicKey.serialize() == rootPublicKeyString)
        #expect(try OpalCrypto.Key.ExtendedPrivate(rootPrivateKeyString) == rootKey)
        #expect(try OpalCrypto.Key.ExtendedPublic(rootPublicKeyString) == rootKey.publicKey)

        let hardenedChild = try rootKey.derived(indices: [0x8000_0000])
        #expect(hardenedChild.serialize() == hardenedChildPrivateKeyString)
        #expect(hardenedChild.publicKey.serialize() == hardenedChildPublicKeyString)

        let grandchild = try rootKey.derived(indices: [0x8000_0000, 1])
        #expect(grandchild.serialize() == grandchildPrivateGrandchildString)
        #expect(grandchild.publicKey.serialize() == grandchildPublicGrandchildString)

        let derivedFromPublic = try OpalCrypto.Key.ExtendedPublic(hardenedChildPublicKeyString)
            .derived(indices: [1])
        #expect(derivedFromPublic.serialize() == grandchildPublicGrandchildString)
    }

    @Test("Reject hardened public derivation")
    func rejectHardenedPublicDerivation() throws {
        let publicKey = try OpalCrypto.Key.ExtendedPublic(hardenedChildPublicKeyString)

        do {
            _ = try publicKey.derived(indices: [0x8000_0000])
            Issue.record("Expected hardened public derivation error.")
        } catch let error as OpalCrypto.Key.ExtendedPublic.Error {
            #expect(error == .hardenedDerivationRequiresPrivateKey)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject extended-key root seeds outside the BIP32 byte range")
    func rejectExtendedKeyRootSeedsOutsideTheBip32ByteRange() {
        for invalidSeedLength in [0, 1, 15, 65] {
            let invalidSeed = Data(repeating: 0x01, count: invalidSeedLength)

            do {
                _ = try OpalCrypto.Key.Seed(rawRepresentation: invalidSeed)
                Issue.record(
                    "Expected invalid seed-length error for out-of-range seed length \(invalidSeedLength)."
                )
            } catch let error as OpalCrypto.Key.ExtendedPrivate.Error {
                #expect(error == .invalidSeedLength(actual: invalidSeedLength))
            } catch {
                Issue.record(
                    "Unexpected error type for seed length \(invalidSeedLength): \(error)"
                )
            }
        }
    }

    @Test("Extended-key serialization preserves parent fingerprint and child index")
    func extendedKeySerializationPreservesParentFingerprintAndChildIndex() throws {
        let rootKey = try OpalCrypto.Key.ExtendedPrivate.root(
            seed: OpalCrypto.Key.Seed(rawRepresentation: Data(hexadecimal: seedHex))
        )
        let hardenedChild = try rootKey.derived(indices: [0x8000_0000])
        let reparsedHardenedChild = try OpalCrypto.Key.ExtendedPrivate(
            hardenedChild.serialize()
        )
        let expectedRootFingerprint = Data(
            OpalCrypto.Hashing.hash160(rootKey.publicKey.publicKey.rawRepresentation).prefix(4)
        )

        #expect(hardenedChild.parentFingerprint.rawRepresentation == expectedRootFingerprint)
        #expect(hardenedChild.childIndex == 0x8000_0000)
        #expect(reparsedHardenedChild.parentFingerprint == hardenedChild.parentFingerprint)
        #expect(reparsedHardenedChild.childIndex == hardenedChild.childIndex)

        let publicGrandchild = try OpalCrypto.Key.ExtendedPublic(
            hardenedChildPublicKeyString
        ).derived(indices: [1])
        let reparsedPublicGrandchild = try OpalCrypto.Key.ExtendedPublic(
            publicGrandchild.serialize()
        )
        let expectedParentFingerprint = Data(
            OpalCrypto.Hashing.hash160(
                (try OpalCrypto.Key.ExtendedPublic(hardenedChildPublicKeyString)).publicKey.rawRepresentation
            ).prefix(4)
        )

        #expect(publicGrandchild.parentFingerprint.rawRepresentation == expectedParentFingerprint)
        #expect(publicGrandchild.childIndex == 1)
        #expect(reparsedPublicGrandchild.parentFingerprint == publicGrandchild.parentFingerprint)
        #expect(reparsedPublicGrandchild.childIndex == publicGrandchild.childIndex)
    }

    @Test("Extended public-key payload init rejects invalid internal payloads without trapping")
    func extendedPublicKeyPayloadInitRejectsInvalidInternalPayloadsWithoutTrapping() throws {
        let privateKeyPayload = try ExtendedKeyPayloadModel(
            kind: .privateKey,
            depth: 0,
            parentFingerprintUInt32BigEndian: 0,
            childIndex: 0,
            chainCode: Data(repeating: 0x11, count: 32),
            keyData: Data(privateKeyBytes)
        )
        let malformedPublicPayload = ExtendedKeyPayloadModel.makeTrustedDerivedPublicKey(
            depth: 1,
            parentFingerprintUInt32BigEndian: 0x1234_5678,
            childIndex: 7,
            chainCode: Data(repeating: 0x22, count: 32),
            publicKeyData33Bytes: Data([0x02] + Array(repeating: 0x00, count: 32))
        )

        do {
            _ = try OpalCrypto.Key.ExtendedPublic(payload: privateKeyPayload)
            Issue.record("Expected invalid version error for a private-key payload.")
        } catch let error as OpalCrypto.Key.ExtendedPublic.Error {
            #expect(error == .invalidVersion(actual: ExtendedKeyPayloadModel.privateVersion))
        } catch {
            Issue.record("Unexpected error type for private-key payload: \(error)")
        }

        do {
            _ = try OpalCrypto.Key.ExtendedPublic(payload: malformedPublicPayload)
            Issue.record("Expected invalid public-key error for malformed payload.")
        } catch let error as OpalCrypto.Key.ExtendedPublic.Error {
            #expect(error == .invalidPublicKey)
        } catch {
            Issue.record("Unexpected error type for malformed public-key payload: \(error)")
        }
    }

    @Test("Extended private-key parsing reports malformed private-key prefix as key material")
    func extendedPrivateKeyParsingReportsMalformedPrivateKeyPrefixAsKeyMaterial() throws {
        var payload = try Base58CheckCodecModel.decode(rootPrivateKeyString, minimumPayloadLength: 78)
        payload[45] = 0x01
        let serialized = Base58CheckCodecModel.encode(payload: payload)

        do {
            _ = try OpalCrypto.Key.ExtendedPrivate(serialized)
            Issue.record("Expected invalid private-key error for malformed xprv prefix.")
        } catch let error as OpalCrypto.Key.ExtendedPrivate.Error {
            #expect(error == .invalidPrivateKey)
        } catch {
            Issue.record("Unexpected error type for malformed xprv prefix: \(error)")
        }
    }

    @Test("Extended-key child-derivation wrappers reject the wrong payload kind early")
    func extendedKeyChildDerivationWrappersRejectTheWrongPayloadKindEarly() throws {
        let privateKeyPayload = try ExtendedKeyDerivationModel.makeRootPrivateKey(
            seed: Data(hexadecimal: seedHex)
        )
        let publicKeyPayload = try ExtendedKeyDerivationModel.makePublicKey(
            from: privateKeyPayload
        )

        do {
            _ = try ExtendedKeyDerivationModel.derivePrivateChild(
                from: publicKeyPayload,
                index: 1
            )
            Issue.record("Expected invalid key-kind error for public -> private derivation.")
        } catch let error as ExtendedKeyDerivationModel.Error {
            #expect(error == .invalidKeyKind)
        } catch {
            Issue.record("Unexpected error type for public -> private derivation: \(error)")
        }

        do {
            _ = try ExtendedKeyDerivationModel.derivePublicChild(
                from: privateKeyPayload,
                index: 1
            )
            Issue.record("Expected invalid key-kind error for private -> public derivation.")
        } catch let error as ExtendedKeyDerivationModel.Error {
            #expect(error == .invalidKeyKind)
        } catch {
            Issue.record("Unexpected error type for private -> public derivation: \(error)")
        }
    }

    private let privateKeyBytes = Array(repeating: UInt8(0x00), count: 31) + [0x01]
    private let compressedWalletImportFormatString = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    private let uncompressedWalletImportFormatString = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"
    private let invalidChecksumWalletImportFormatString = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWm"
    private let testnetWalletImportFormatString = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA"

    private let seedHex = "000102030405060708090a0b0c0d0e0f"
    private let rootPrivateKeyString = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    private let rootPublicKeyString = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    private let hardenedChildPrivateKeyString = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    private let hardenedChildPublicKeyString = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
    private let grandchildPrivateGrandchildString = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    private let grandchildPublicGrandchildString = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
}
