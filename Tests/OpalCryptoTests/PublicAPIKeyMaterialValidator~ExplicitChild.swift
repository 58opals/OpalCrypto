// PublicAPIKeyMaterialValidator~ExplicitChild.swift

import Foundation
import Testing
@testable import OpalCrypto

extension PublicAPIKeyMaterialValidator {
    @Test("Explicit chain code derives matching public and signing children")
    func explicitChainCodeDerivesMatchingPublicAndSigningChildren() throws {
        let chainCode = try OpalCrypto.Key.ChainCode(
            rawRepresentation: try Data(
                hexadecimal:
                    "e4597ed066ca88ad4abb72f290251acaa5b680e574dad641b6bc4e38fbfa34b1"
            )
        )
        let expectedParentPublicKey = try OpalCrypto.Secp256k1.PublicKey(
            rawRepresentation: try Data(
                hexadecimal:
                    "03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8"
            )
        )
        let expectedChildPublicKey = try Data(
            hexadecimal:
                "039f3c77288d6e9c76a599f14c3f72bbd9f87d80fc12263e057eb234b435d05979"
        )

        let publicChild = try OpalCrypto.Key
            .deriveNonHardenedChildPublicKey(
                from: expectedParentPublicKey,
                chainCode: chainCode,
                at: 0
            )
        #expect(publicChild.rawRepresentation == expectedChildPublicKey)

        let parentSigningKey = try OpalCrypto.Secp256k1.SigningKey(
            rawRepresentation: OpalCryptoTestSupport.makePrivateKey(13)
        )
        #expect(
            parentSigningKey.publicKey.rawRepresentation
                == expectedParentPublicKey.rawRepresentation
        )

        let signingChild = try OpalCrypto.Key
            .deriveNonHardenedChildSigningKey(
                from: parentSigningKey,
                chainCode: chainCode,
                at: 0
            )
        let expectedChildPrivateKey = try Data(
            hexadecimal:
                "93a80be0074cdf692f576277bd86ebad3a42d2767388eab1ce5d7c8556aff957"
        )
        let expectedSigningChild = try OpalCrypto.Secp256k1.SigningKey(
            rawRepresentation: expectedChildPrivateKey
        )

        #expect(signingChild == expectedSigningChild)
        #expect(
            signingChild.publicKey.rawRepresentation
                == expectedChildPublicKey
        )
        #expect(signingChild.publicKey == publicChild)
        #expect(String(reflecting: signingChild).contains("redacted"))
        #expect(
            String(reflecting: signingChild).contains(
                expectedChildPrivateKey
                    .map { String(format: "%02x", $0) }
                    .joined()
            ) == false
        )

        let digest = try OpalCrypto.Signature.Digest(
            rawRepresentation: Data(repeating: 0xA5, count: 32)
        )
        let signature = try signingChild.signSchnorr(digest: digest)
        #expect(
            try signature.verify(
                digest: digest,
                publicKey: publicChild
            )
        )
    }

    @Test("Explicit chain code operations reject hardened indices")
    func explicitChainCodeOperationsRejectHardenedIndices() throws {
        let chainCode = try OpalCrypto.Key.ChainCode(
            rawRepresentation: Data(repeating: 0x42, count: 32)
        )
        let parentSigningKey = try OpalCrypto.Secp256k1.SigningKey(
            rawRepresentation: OpalCryptoTestSupport.makePrivateKey(13)
        )
        let hardenedIndex: UInt32 = 0x8000_0000

        #expect(
            throws: OpalCrypto.Key.ChildDerivationError
                .hardenedIndex(hardenedIndex)
        ) {
            _ = try OpalCrypto.Key.deriveNonHardenedChildPublicKey(
                from: parentSigningKey.publicKey,
                chainCode: chainCode,
                at: hardenedIndex
            )
        }
        #expect(
            throws: OpalCrypto.Key.ChildDerivationError
                .hardenedIndex(hardenedIndex)
        ) {
            _ = try OpalCrypto.Key.deriveNonHardenedChildSigningKey(
                from: parentSigningKey,
                chainCode: chainCode,
                at: hardenedIndex
            )
        }
    }

    @Test("Explicit child operations match official BIP-32 vector 1")
    func explicitChildOperationsMatchOfficialBIP32Vector1() throws {
        let parentPrivate = try OpalCrypto.Key.ExtendedPrivate(
            hardenedChildPrivateKeyString
        )
        let parentPublic = try OpalCrypto.Key.ExtendedPublic(
            hardenedChildPublicKeyString
        )
        let expectedPrivate = try OpalCrypto.Key.ExtendedPrivate(
            grandchildPrivateGrandchildString
        )
        let expectedPublic = try OpalCrypto.Key.ExtendedPublic(
            grandchildPublicGrandchildString
        )

        let publicChild = try OpalCrypto.Key
            .deriveNonHardenedChildPublicKey(
                from: parentPublic.publicKey,
                chainCode: parentPublic.chainCode,
                at: 1
            )
        let signingChild = try OpalCrypto.Key
            .deriveNonHardenedChildSigningKey(
                from: parentPrivate.signingKey,
                chainCode: parentPrivate.chainCode,
                at: 1
            )

        #expect(parentPrivate.chainCode == parentPublic.chainCode)
        #expect(publicChild == expectedPublic.publicKey)
        #expect(signingChild == expectedPrivate.signingKey)
        #expect(signingChild.publicKey == publicChild)
    }
}
