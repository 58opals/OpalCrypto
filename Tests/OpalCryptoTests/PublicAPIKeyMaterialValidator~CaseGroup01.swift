// PublicAPIKeyMaterialValidator~CaseGroup01.swift

import Foundation
import Testing
@testable import OpalCrypto

extension PublicAPIKeyMaterialValidator {
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
        let serialized = Base58CheckCodec.encode(payload: truncatedPayload)

        #expect(throws: OpalCrypto.Key.WIF.Error.invalidPayloadLength(actual: 32)) {
            _ = try OpalCrypto.Key.WIF(serialized)
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

    @Test("Extended private signing key signs without extracting raw private key")
    func extendedPrivateSigningKeySignsWithoutExtractingRawPrivateKey() throws {
        let rootKey = try OpalCrypto.Key.ExtendedPrivate.root(
            seed: OpalCrypto.Key.Seed(rawRepresentation: Data(hexadecimal: seedHex))
        )
        let signingKey = rootKey.signingKey
        let digest = try OpalCrypto.Signature.Digest(
            rawRepresentation: OpalCrypto.Hashing.sha256(Data("opal-extended-signing-key".utf8))
        )
        let signature = try signingKey.signECDSA(
            digest: digest,
            format: .raw
        )

        #expect(signingKey.publicKey == rootKey.publicKey.publicKey)
        #expect(signingKey.verificationKey.publicKey == rootKey.publicKey.publicKey)
        #expect(try signature.verify(digest: digest, verificationKey: signingKey.verificationKey))
    }

    @Test("Wallet import format signing key signs without extracting raw private key at the call site")
    func walletImportFormatSigningKeySignsWithoutExtractingRawPrivateKeyAtTheCallSite() throws {
        let walletImportFormat = try OpalCrypto.Key.WIF(compressedWalletImportFormatString)
        let signingKey = try walletImportFormat.makeSigningKey()
        let digest = try OpalCrypto.Signature.Digest(
            rawRepresentation: OpalCrypto.Hashing.sha256(Data("opal-wif-signing-key".utf8))
        )
        let signature = try signingKey.signSchnorr(digest: digest)

        #expect(try signature.verify(digest: digest, verificationKey: signingKey.verificationKey))
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

    @Test("Extended-key root seed values normalize sliced raw input")
    func normalizeExtendedKeyRootSeedValuesFromSlicedRawInput() throws {
        let seedData = try Data(hexadecimal: seedHex)
        let slicedSeedData = (Data([0xFF]) + seedData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let seed = try OpalCrypto.Key.Seed(rawRepresentation: slicedSeedData)

        #expect(seed.rawRepresentation == seedData)
        #expect(seed.rawRepresentation.startIndex == 0)
        #expect(seed.rawRepresentation[0] == 0x00)
    }

    @Test("Extended-key chain-code values normalize sliced raw input")
    func normalizeExtendedKeyChainCodeValuesFromSlicedRawInput() throws {
        let chainCodeData = Data(repeating: 0x11, count: 32)
        let slicedChainCodeData = (Data([0xFF]) + chainCodeData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let chainCode = try OpalCrypto.Key.ChainCode(rawRepresentation: slicedChainCodeData)

        #expect(chainCode.rawRepresentation == chainCodeData)
        #expect(chainCode.rawRepresentation.startIndex == 0)
        #expect(chainCode.rawRepresentation[0] == 0x11)
    }

    @Test("Extended-key fingerprint values normalize sliced raw input")
    func normalizeExtendedKeyFingerprintValuesFromSlicedRawInput() throws {
        let fingerprintData = Data([0x12, 0x34, 0x56, 0x78])
        let slicedFingerprintData = (Data([0xFF]) + fingerprintData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let fingerprint = try OpalCrypto.Key.Fingerprint(rawRepresentation: slicedFingerprintData)

        #expect(fingerprint.rawRepresentation == fingerprintData)
        #expect(fingerprint.rawRepresentation.startIndex == 0)
        #expect(fingerprint.rawRepresentation[0] == 0x12)
    }

    @Test("Extended-key payloads normalize sliced key material")
    func normalizeExtendedKeyPayloadsFromSlicedKeyMaterial() throws {
        let chainCodeData = Data(repeating: 0x11, count: 32)
        let slicedChainCodeData = (Data([0xFF]) + chainCodeData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let slicedPrivateKeyData = (Data([0xFF]) + Data(privateKeyBytes) + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let payload = try ExtendedKeyPayloadModel(
            kind: .privateKey,
            depth: 0,
            parentFingerprintUInt32BigEndian: 0,
            childIndex: 0,
            chainCode: slicedChainCodeData,
            keyData: slicedPrivateKeyData
        )

        #expect(payload.chainCode == chainCodeData)
        #expect(payload.chainCode.startIndex == 0)
        #expect(payload.chainCode[0] == 0x11)
        #expect(payload.keyData == Data(privateKeyBytes))
        #expect(payload.keyData.startIndex == 0)
        #expect(payload.keyData[0] == 0x00)
    }
}
