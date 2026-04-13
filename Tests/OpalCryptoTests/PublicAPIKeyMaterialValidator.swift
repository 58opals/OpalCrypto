// PublicAPIKeyMaterialValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API key material validation")
struct PublicAPIKeyMaterialValidator {
    @Test("Round-trip mainnet wallet import format and reject invalid variants")
    func roundTripMainnetWalletImportFormatAndRejectInvalidVariants() throws {
        let privateKey = Data(privateKeyBytes)

        let compressedWalletImportFormat = try OpalCrypto.Key.WIF(privateKey: privateKey, isCompressed: true)
        #expect(try compressedWalletImportFormat.serialize() == compressedWalletImportFormatString)
        #expect(try OpalCrypto.Key.WIF(compressedWalletImportFormatString) == compressedWalletImportFormat)

        let uncompressedWalletImportFormat = try OpalCrypto.Key.WIF(privateKey: privateKey, isCompressed: false)
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

    @Test("Round-trip extended keys and derive raw child indices")
    func roundTripExtendedKeysAndDeriveRawChildIndices() throws {
        let rootKey = try OpalCrypto.Key.ExtendedPrivateKey.root(seed: Data(hexadecimal: seedHex))
        #expect(rootKey.serialize() == rootPrivateKeyString)
        #expect(rootKey.publicKey.serialize() == rootPublicKeyString)
        #expect(try OpalCrypto.Key.ExtendedPrivateKey(rootPrivateKeyString) == rootKey)
        #expect(try OpalCrypto.Key.ExtendedPublicKey(rootPublicKeyString) == rootKey.publicKey)

        let hardenedChild = try rootKey.derived(indices: [0x8000_0000])
        #expect(hardenedChild.serialize() == hardenedChildPrivateKeyString)
        #expect(hardenedChild.publicKey.serialize() == hardenedChildPublicKeyString)

        let grandchild = try rootKey.derived(indices: [0x8000_0000, 1])
        #expect(grandchild.serialize() == grandchildPrivateGrandchildString)
        #expect(grandchild.publicKey.serialize() == grandchildPublicGrandchildString)

        let derivedFromPublic = try OpalCrypto.Key.ExtendedPublicKey(hardenedChildPublicKeyString)
            .derived(indices: [1])
        #expect(derivedFromPublic.serialize() == grandchildPublicGrandchildString)
    }

    @Test("Reject hardened public derivation")
    func rejectHardenedPublicDerivation() throws {
        let publicKey = try OpalCrypto.Key.ExtendedPublicKey(hardenedChildPublicKeyString)

        do {
            _ = try publicKey.derived(indices: [0x8000_0000])
            Issue.record("Expected hardened public derivation error.")
        } catch let error as OpalCrypto.Key.ExtendedPublicKey.Error {
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
                _ = try OpalCrypto.Key.ExtendedPrivateKey.root(seed: invalidSeed)
                Issue.record(
                    "Expected invalid derived key error for out-of-range seed length \(invalidSeedLength)."
                )
            } catch let error as OpalCrypto.Key.ExtendedPrivateKey.Error {
                #expect(error == .invalidDerivedKey)
            } catch {
                Issue.record(
                    "Unexpected error type for seed length \(invalidSeedLength): \(error)"
                )
            }
        }
    }

    @Test("Extended-key serialization preserves parent fingerprint and child index")
    func extendedKeySerializationPreservesParentFingerprintAndChildIndex() throws {
        let rootKey = try OpalCrypto.Key.ExtendedPrivateKey.root(seed: Data(hexadecimal: seedHex))
        let hardenedChild = try rootKey.derived(indices: [0x8000_0000])
        let reparsedHardenedChild = try OpalCrypto.Key.ExtendedPrivateKey(
            hardenedChild.serialize()
        )
        let expectedRootFingerprint = Data(
            OpalCrypto.Hashing.computeHash160(rootKey.publicKey.publicKey).prefix(4)
        )

        #expect(hardenedChild.parentFingerprint == expectedRootFingerprint)
        #expect(hardenedChild.childIndex == 0x8000_0000)
        #expect(reparsedHardenedChild.parentFingerprint == hardenedChild.parentFingerprint)
        #expect(reparsedHardenedChild.childIndex == hardenedChild.childIndex)

        let publicGrandchild = try OpalCrypto.Key.ExtendedPublicKey(
            hardenedChildPublicKeyString
        ).derived(indices: [1])
        let reparsedPublicGrandchild = try OpalCrypto.Key.ExtendedPublicKey(
            publicGrandchild.serialize()
        )
        let expectedParentFingerprint = Data(
            OpalCrypto.Hashing.computeHash160(
                (try OpalCrypto.Key.ExtendedPublicKey(hardenedChildPublicKeyString)).publicKey
            ).prefix(4)
        )

        #expect(publicGrandchild.parentFingerprint == expectedParentFingerprint)
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
            _ = try OpalCrypto.Key.ExtendedPublicKey(payload: privateKeyPayload)
            Issue.record("Expected invalid version error for a private-key payload.")
        } catch let error as OpalCrypto.Key.ExtendedPublicKey.Error {
            #expect(error == .invalidVersion(actual: ExtendedKeyPayloadModel.privateVersion))
        } catch {
            Issue.record("Unexpected error type for private-key payload: \(error)")
        }

        do {
            _ = try OpalCrypto.Key.ExtendedPublicKey(payload: malformedPublicPayload)
            Issue.record("Expected invalid public-key error for malformed payload.")
        } catch let error as OpalCrypto.Key.ExtendedPublicKey.Error {
            #expect(error == .invalidPublicKey)
        } catch {
            Issue.record("Unexpected error type for malformed public-key payload: \(error)")
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

private extension Data {
    init(hexadecimal: String) throws {
        let normalized = hexadecimal.trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalized.count.isMultiple(of: 2) else {
            throw HexadecimalDataError.invalidLength
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(normalized.count / 2)
        var cursor = normalized.startIndex
        while cursor < normalized.endIndex {
            let nextCursor = normalized.index(cursor, offsetBy: 2)
            let pair = normalized[cursor..<nextCursor]
            guard let byte = UInt8(pair, radix: 16) else {
                throw HexadecimalDataError.invalidCharacter
            }
            bytes.append(byte)
            cursor = nextCursor
        }
        self = Data(bytes)
    }
}

private enum HexadecimalDataError: Error {
    case invalidLength
    case invalidCharacter
}
