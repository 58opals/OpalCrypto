// PerformanceOptimizationKeyCacheValidator~CaseGroup02.swift

import Foundation
import Testing
@testable import OpalCrypto

extension PerformanceOptimizationKeyCacheValidator {
    @Test("Parsed public-key tweak-add matches the raw and cached verification-key paths")
    func validateParsedPublicKeyTweakAddMatchesTheRawAndCachedVerificationKeyPaths() throws {
        let privateKey = OpalCryptoTestSupport.makePrivateKey(31)
        let tweak = OpalCryptoTestSupport.makePrivateKey(37)
        let typedPrivateKey = try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: privateKey)
        let typedTweak = try OpalCrypto.Secp256k1.Scalar(rawRepresentation: tweak)
        let compressedPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(
            from: typedPrivateKey
        ).rawRepresentation
        let parsedPublicKeyModel = try ParsedPublicKeyModel(publicKeyData: compressedPublicKey)
        let verificationKeyModel = VerificationKeyModel(parsedPublicKeyModel: parsedPublicKeyModel)

        let rawTweakedPublicKey = try OpalCrypto.Secp256k1.tweakAddPublicKey(
            try OpalCrypto.Secp256k1.PublicKey(rawRepresentation: compressedPublicKey),
            tweak: typedTweak
        ).rawRepresentation
        let parsedTweakedPublicKey = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .tweakAddPublicKey(parsedPublicKeyModel, tweakData32Bytes: tweak, format: .compressed)
        let cachedTweakedPublicKey = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .tweakAddPublicKey(verificationKeyModel, tweakData32Bytes: tweak, format: .compressed)

        #expect(parsedTweakedPublicKey == rawTweakedPublicKey)
        #expect(cachedTweakedPublicKey == rawTweakedPublicKey)
        #expect(parsedTweakedPublicKey == cachedTweakedPublicKey)
    }

    @Test("Extended public and private derivation remain aligned with cached key fast paths")
    func validateExtendedPublicAndPrivateDerivationRemainAlignedWithCachedKeyFastPaths() throws {
        let seed = try OpalCrypto.Key.Seed(rawRepresentation: Data((0..<16).map(UInt8.init)))
        let rootPrivateKey = try OpalCrypto.Key.ExtendedPrivate.root(seed: seed)
        let hardenedPrivateChild = try rootPrivateKey.derived(indices: [0x8000_0000])
        let derivedFromPrivate = try rootPrivateKey.derived(indices: [0x8000_0000, 1, 2, 3]).publicKey
        let derivedFromPublic = try hardenedPrivateChild.publicKey.derived(indices: [1, 2, 3])

        #expect(derivedFromPublic == derivedFromPrivate)
        #expect(derivedFromPublic.depth == derivedFromPrivate.depth)
        #expect(derivedFromPublic.childIndex == derivedFromPrivate.childIndex)
        #expect(derivedFromPublic.parentFingerprint == derivedFromPrivate.parentFingerprint)
        #expect(derivedFromPublic.chainCode == derivedFromPrivate.chainCode)
    }
}
