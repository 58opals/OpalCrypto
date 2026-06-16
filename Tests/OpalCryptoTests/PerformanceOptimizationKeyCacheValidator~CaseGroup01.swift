// PerformanceOptimizationKeyCacheValidator~CaseGroup01.swift

import Foundation
import Testing
@testable import OpalCrypto

extension PerformanceOptimizationKeyCacheValidator {
    @Test("Parallel mnemonic word-list loads return consistent results")
    func parallelMnemonicWordListLoadsReturnConsistentResults() async throws {
        let wordLists = try await withThrowingTaskGroup(
            of: OpalCrypto.Key.Mnemonic.WordList.self,
            returning: [OpalCrypto.Key.Mnemonic.WordList].self
        ) { group in
            for _ in 0..<8 {
                group.addTask { try OpalCrypto.Key.Mnemonic.WordList.load(.english) }
                group.addTask { try OpalCrypto.Key.Mnemonic.WordList.load(.korean) }
            }

            var resolvedWordLists: [OpalCrypto.Key.Mnemonic.WordList] = []
            for try await wordList in group {
                resolvedWordLists.append(wordList)
            }
            return resolvedWordLists
        }

        let englishWordLists = wordLists.filter { $0.language == .english }
        let koreanWordLists = wordLists.filter { $0.language == .korean }
        let referenceEnglishWordList = try #require(englishWordLists.first)
        let referenceKoreanWordList = try #require(koreanWordLists.first)

        #expect(englishWordLists.count == 8)
        #expect(koreanWordLists.count == 8)
        #expect(englishWordLists.allSatisfy { $0 == referenceEnglishWordList })
        #expect(koreanWordLists.allSatisfy { $0 == referenceKoreanWordList })
    }

    @Test("Parsed public-key model canonicalizes encodings and caches the HDKD fingerprint")
    func validateParsedPublicKeyModelCanonicalizesEncodingsAndCachesTheHDKDFingerprint() throws {
        let privateKey = OpalCryptoTestSupport.makePrivateKey(7)
        let compressedPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(
            from: OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: privateKey)
        ).rawRepresentation
        let compressedPoint = try PublicKeyParserModel.parsePublicKey(compressedPublicKey)
        let uncompressedPublicKey = compressedPoint.encodeUncompressed65()
        let compressedParsedPublicKeyModel = try ParsedPublicKeyModel(publicKeyData: compressedPublicKey)
        let uncompressedParsedPublicKeyModel = try ParsedPublicKeyModel(publicKeyData: uncompressedPublicKey)

        #expect(compressedParsedPublicKeyModel == uncompressedParsedPublicKeyModel)
        #expect(compressedParsedPublicKeyModel.compressedPublicKeyData == compressedPublicKey)
        #expect(
            compressedParsedPublicKeyModel.fingerprintUInt32BigEndian
                == SecureHash160Model.hash(compressedPublicKey).uint32BigEndian(at: 0)
        )
    }

    @Test("Parsed private-key model caches the compressed public key and HDKD fingerprint")
    func validateParsedPrivateKeyModelCachesTheCompressedPublicKeyAndHDKDFingerprint() throws {
        let privateKey = OpalCryptoTestSupport.makePrivateKey(9)
        let expectedCompressedPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(
            from: OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: privateKey)
        ).rawRepresentation
        let parsedPrivateKeyModel = try ParsedPrivateKeyModel(privateKeyData32Bytes: privateKey)

        #expect(parsedPrivateKeyModel.compressedPublicKeyData == expectedCompressedPublicKey)
        #expect(
            parsedPrivateKeyModel.compressedPublicKeyFingerprintUInt32BigEndian
                == SecureHash160Model.hash(expectedCompressedPublicKey).uint32BigEndian(at: 0)
        )
    }

    @Test("Trusted extended-key payload factories match validated constructors on known-good inputs")
    func validateTrustedExtendedKeyPayloadFactoriesMatchValidatedConstructorsOnKnownGoodInputs() throws {
        let privateKey = OpalCryptoTestSupport.makePrivateKey(41)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(
            from: OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: privateKey)
        ).rawRepresentation
        let parentFingerprint = UInt32(0x1234_5678)
        let chainCode = Data((0..<32).map { UInt8(($0 * 9) & 0xff) })

        let validatedPrivatePayload = try ExtendedKeyPayloadModel(
            kind: .privateKey,
            depth: 1,
            parentFingerprintUInt32BigEndian: parentFingerprint,
            childIndex: 7,
            chainCode: chainCode,
            keyData: privateKey
        )
        let trustedPrivatePayload = ExtendedKeyPayloadModel.makeTrustedDerivedPrivateKey(
            depth: 1,
            parentFingerprintUInt32BigEndian: parentFingerprint,
            childIndex: 7,
            chainCode: chainCode,
            privateKeyData32Bytes: privateKey
        )
        let validatedPublicPayload = try ExtendedKeyPayloadModel(
            kind: .publicKey,
            depth: 1,
            parentFingerprintUInt32BigEndian: parentFingerprint,
            childIndex: 7,
            chainCode: chainCode,
            keyData: publicKey
        )
        let trustedPublicPayload = ExtendedKeyPayloadModel.makeTrustedDerivedPublicKey(
            depth: 1,
            parentFingerprintUInt32BigEndian: parentFingerprint,
            childIndex: 7,
            chainCode: chainCode,
            publicKeyData33Bytes: publicKey
        )

        expectTrustedPayloadMatchesValidatedPayload(
            trustedPrivatePayload,
            validatedPayload: validatedPrivatePayload
        )
        expectTrustedPayloadMatchesValidatedPayload(
            trustedPublicPayload,
            validatedPayload: validatedPublicPayload
        )
    }

    @Test("Verification-key verification parity survives the parsed-key cache split")
    func validateVerificationKeyVerificationParitySurvivesTheParsedKeyCacheSplit() throws {
        let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(29)
        let message = Data("opal-ecdsa-cache-split".utf8)
        let digest = try OpalCrypto.Signature.Digest(rawRepresentation: Data(repeating: 0x29, count: 32))
        let compressedPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
            .rawRepresentation
        let verificationKeyModel = VerificationKeyModel(
            parsedPublicKeyModel: try ParsedPublicKeyModel(publicKeyData: compressedPublicKey)
        )
        let ecdsaSignature = try OpalCrypto.Signature.ECDSA.sign(
            message: message,
            privateKey: privateKey,
            format: .der
        ).rawRepresentation
        let schnorrSignature = try OpalCrypto.Signature.Schnorr.sign(
            digest: digest,
            privateKey: privateKey,
            noncePolicy: .bip340Deterministic
        ).rawRepresentation

        let rawEcdsaResult = try EllipticCurveDigitalSignatureAlgorithmModel.verify(
            signature: ecdsaSignature,
            message: message,
            publicKey: compressedPublicKey,
            format: .ecdsa(.distinguishedEncodingRules)
        )
        let cachedEcdsaResult = try EllipticCurveDigitalSignatureAlgorithmModel.verify(
            signature: ecdsaSignature,
            message: message,
            verificationKeyModel: verificationKeyModel,
            format: .ecdsa(.distinguishedEncodingRules)
        )
        let rawSchnorrResult = try EllipticCurveDigitalSignatureAlgorithmModel.verify(
            signature: schnorrSignature,
            message: digest.rawRepresentation,
            publicKey: compressedPublicKey,
            format: .schnorr
        )
        let cachedSchnorrResult = try EllipticCurveDigitalSignatureAlgorithmModel.verify(
            signature: schnorrSignature,
            message: digest.rawRepresentation,
            verificationKeyModel: verificationKeyModel,
            format: .schnorr
        )

        #expect(rawEcdsaResult == cachedEcdsaResult)
        #expect(rawSchnorrResult == cachedSchnorrResult)
        #expect(rawEcdsaResult)
        #expect(rawSchnorrResult)
        #expect(cachedEcdsaResult)
        #expect(cachedSchnorrResult)
    }
}
