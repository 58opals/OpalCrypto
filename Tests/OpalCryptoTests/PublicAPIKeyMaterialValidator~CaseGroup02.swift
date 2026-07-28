// PublicAPIKeyMaterialValidator~CaseGroup02.swift

import Foundation
import Testing
@testable import OpalCrypto

extension PublicAPIKeyMaterialValidator {
    @Test("Extended-key serialization preserves parent fingerprint and child index")
    func validateExtendedKeySerializationPreservesParentFingerprintAndChildIndex() throws {
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
        var payload = try Base58CheckCodec.decode(
            rootPrivateKeyString,
            minimumPayloadLength: 78,
            maximumPayloadLength: 78
        )
        payload[45] = 0x01
        let serialized = Base58CheckCodec.encode(payload: payload)

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
}
