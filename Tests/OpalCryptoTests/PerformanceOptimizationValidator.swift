// PerformanceOptimizationValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Performance optimization validation")
struct PerformanceOptimizationValidator {
    @Test("Batch compressed public-key derivation preserves ordering in the parallel path")
    func batchCompressedPublicKeyDerivationPreservesOrderingInTheParallelPath() async throws {
        let privateKeys = (1...256).map(makePrivateKey)
        let batchPublicKeys = try await OpalCrypto.Secp256k1.deriveCompressedPublicKeys(
            from: privateKeys
        )
        let singlePublicKeys = try privateKeys.map {
            try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: $0)
        }

        #expect(batchPublicKeys == singlePublicKeys)
    }

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
    func parsedPublicKeyModelCanonicalizesEncodingsAndCachesTheHdkdFingerprint() throws {
        let privateKey = makePrivateKey(7)
        let compressedPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: privateKey
        )
        let compressedPoint = try PublicKeyParserModel.parsePublicKey(compressedPublicKey)
        let uncompressedPublicKey = compressedPoint.encodeUncompressed65()
        let compressedParsedPublicKeyModel = try ParsedPublicKeyModel(
            publicKeyData: compressedPublicKey
        )
        let uncompressedParsedPublicKeyModel = try ParsedPublicKeyModel(
            publicKeyData: uncompressedPublicKey
        )

        #expect(compressedParsedPublicKeyModel == uncompressedParsedPublicKeyModel)
        #expect(compressedParsedPublicKeyModel.compressedPublicKeyData == compressedPublicKey)
        #expect(
            compressedParsedPublicKeyModel.fingerprintUInt32BigEndian
                == SecureHash160Model.hash(compressedPublicKey).uint32BigEndian(at: 0)
        )
    }

    @Test("Parsed private-key model caches the compressed public key and HDKD fingerprint")
    func parsedPrivateKeyModelCachesTheCompressedPublicKeyAndHdkdFingerprint() throws {
        let privateKey = makePrivateKey(9)
        let expectedCompressedPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: privateKey
        )
        let parsedPrivateKeyModel = try ParsedPrivateKeyModel(privateKeyData32Bytes: privateKey)

        #expect(parsedPrivateKeyModel.compressedPublicKeyData == expectedCompressedPublicKey)
        #expect(
            parsedPrivateKeyModel.compressedPublicKeyFingerprintUInt32BigEndian
                == SecureHash160Model.hash(expectedCompressedPublicKey).uint32BigEndian(at: 0)
        )
    }

    @Test("Specialized field sqrt and residue helpers preserve the old exponentiation results")
    func specializedFieldSqrtAndResidueHelpersPreserveTheOldExponentiationResults() throws {
        let fieldElement = try FieldElementModel(
            data32: Data([UInt8](repeating: 0x00, count: 31) + [0x04])
        )
        let squareRoot = try #require(fieldElement.sqrt())
        let expectedSquareRoot = fieldElement.pow(
            exponentBits: FieldPowModel.squareRootExponentBits
        )

        #expect(squareRoot == expectedSquareRoot)
        #expect(
            fieldElement.isQuadraticResidue
                == (fieldElement.pow(exponentBits: FieldPowModel.legendreExponentBits) == .one)
        )
    }

    @Test("Specialized scalar inversion preserves the old exponentiation result")
    func specializedScalarInversionPreservesTheOldExponentiationResult() throws {
        let scalar = try ScalarModel(data32: makePrivateKey(15), requireNonZero: true)

        #expect(
            try scalar.invert()
                == scalar.pow(exponentBits: ScalarPowModel.inversionExponentBits)
        )
    }

    @Test("Trusted extended-key payload factories match validated constructors on known-good inputs")
    func trustedExtendedKeyPayloadFactoriesMatchValidatedConstructorsOnKnownGoodInputs() throws {
        let privateKey = makePrivateKey(41)
        let publicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: privateKey)
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

        #expect(validatedPrivatePayload == trustedPrivatePayload)
        #expect(validatedPrivatePayload.serialize() == trustedPrivatePayload.serialize())
        #expect(validatedPublicPayload == trustedPublicPayload)
        #expect(validatedPublicPayload.serialize() == trustedPublicPayload.serialize())
    }

    @Test("Joint generator and cached-key multiplication matches separate multiplication")
    func jointGeneratorAndCachedKeyMultiplicationMatchesSeparateMultiplication() throws {
        let publicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: makePrivateKey(11)
        )
        let verificationKeyModel = try VerificationKeyModel(publicKeyData: publicKey)
        let generatorScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parseTweakScalar(
                makePrivateKey(13),
                requireNonZero: false
            )
        let verificationKeyScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parseTweakScalar(
                makePrivateKey(17),
                requireNonZero: false
            )

        let expectedPoint = ScalarMultiplicationModel.mulG(generatorScalar).add(
            ScalarMultiplicationModel.mulWithDoubleAndAddLadder(
                verificationKeyScalar,
                verificationKeyModel.affinePoint
            )
        )
        let actualPoint = ScalarMultiplicationModel.mulJointGeneratorAndVerificationKey(
            generatorScalar: generatorScalar,
            verificationKeyScalar: verificationKeyScalar,
            verificationKeyModel: verificationKeyModel
        )

        #expect(actualPoint.convertToAffine() == expectedPoint.convertToAffine())
    }

    @Test("Verification-key verification parity survives the parsed-key cache split")
    func verificationKeyVerificationParitySurvivesTheParsedKeyCacheSplit() throws {
        let privateKey = makePrivateKey(29)
        let message = Data("opal-ecdsa-cache-split".utf8)
        let digest = Data(repeating: 0x29, count: 32)
        let compressedPublicKey = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKey
        )
        let verificationKeyModel = VerificationKeyModel(
            parsedPublicKeyModel: try ParsedPublicKeyModel(publicKeyData: compressedPublicKey)
        )
        let ecdsaSignature = try OpalCrypto.Signature.sign(
            message: message,
            privateKey: privateKey,
            format: .ecdsa(.der)
        )
        let schnorrSignature = try OpalCrypto.Signature.sign(
            message: digest,
            privateKey: privateKey,
            format: .schnorr,
            nonce: .bip340Deterministic
        )

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
            message: digest,
            publicKey: compressedPublicKey,
            format: .schnorr
        )
        let cachedSchnorrResult = try EllipticCurveDigitalSignatureAlgorithmModel.verify(
            signature: schnorrSignature,
            message: digest,
            verificationKeyModel: verificationKeyModel,
            format: .schnorr
        )

        #expect(rawEcdsaResult == cachedEcdsaResult)
        #expect(rawSchnorrResult == cachedSchnorrResult)
        #expect(cachedEcdsaResult)
        #expect(cachedSchnorrResult)
    }

    @Test("Parsed public-key tweak-add matches the raw and cached verification-key paths")
    func parsedPublicKeyTweakAddMatchesTheRawAndCachedVerificationKeyPaths() throws {
        let privateKey = makePrivateKey(31)
        let tweak = makePrivateKey(37)
        let compressedPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: privateKey
        )
        let parsedPublicKeyModel = try ParsedPublicKeyModel(publicKeyData: compressedPublicKey)
        let verificationKeyModel = VerificationKeyModel(parsedPublicKeyModel: parsedPublicKeyModel)

        let rawTweakedPublicKey = try OpalCrypto.Secp256k1.tweakAddPublicKey(
            compressedPublicKey,
            tweak: tweak
        )
        let parsedTweakedPublicKey = try StandardsForEfficientCryptography256k1CurveModel
            .Operation.tweakAddPublicKey(
                parsedPublicKeyModel,
                tweakData32Bytes: tweak,
                format: .compressed
            )
        let cachedTweakedPublicKey = try StandardsForEfficientCryptography256k1CurveModel
            .Operation.tweakAddPublicKey(
                verificationKeyModel,
                tweakData32Bytes: tweak,
                format: .compressed
            )

        #expect(parsedTweakedPublicKey == rawTweakedPublicKey)
        #expect(cachedTweakedPublicKey == rawTweakedPublicKey)
    }

    @Test("Extended public and private derivation remain aligned with cached key fast paths")
    func extendedPublicAndPrivateDerivationRemainAlignedWithCachedKeyFastPaths() throws {
        let seed = Data((0..<16).map(UInt8.init))
        let rootPrivateKey = try OpalCrypto.Key.ExtendedPrivateKey.root(seed: seed)
        let hardenedPrivateChild = try rootPrivateKey.derived(indices: [0x8000_0000])
        let derivedFromPrivate = try rootPrivateKey.derived(
            indices: [0x8000_0000, 1, 2, 3]
        ).publicKey
        let derivedFromPublic = try hardenedPrivateChild.publicKey.derived(
            indices: [1, 2, 3]
        )

        #expect(derivedFromPublic == derivedFromPrivate)
    }

    @Test("Batch compressed public-key derivation from parsed scalars matches data-based and single-key derivation")
    func batchCompressedPublicKeyDerivationFromParsedScalarsMatchesDataBasedAndSingleKeyDerivation()
        async throws {
        let privateKeys = (1...256).map(makePrivateKey)
        let privateKeyScalars = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parsePrivateKeyScalars(
                fromPrivateKeys32: privateKeys,
                assumingValidPrivateKeys: false
            )
        let scalarBatchPublicKeys = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeyScalars: privateKeyScalars,
                executionMode: .automatic
            )
        let dataBatchPublicKeys = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys,
                executionMode: .automatic
            )
        let singlePublicKeys = try privateKeys.map {
            try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: $0)
        }

        #expect(scalarBatchPublicKeys == dataBatchPublicKeys)
        #expect(scalarBatchPublicKeys == singlePublicKeys)
    }

    @Test("Global affine conversion after batch Jacobian multiplication matches single derivation")
    func globalAffineConversionAfterBatchJacobianMultiplicationMatchesSingleDerivation() throws {
        let privateKeys = (1...1024).map(makePrivateKey)
        let privateKeyScalars = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parsePrivateKeyScalars(
                fromPrivateKeys32: privateKeys,
                assumingValidPrivateKeys: false
            )
        let jacobianPoints = StandardsForEfficientCryptography256k1CurveModel.Operation
            .derivePublicKeyJacobianPoints(
                fromPrivateKeyScalars: privateKeyScalars
            )
        let batchPublicKeys = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .encodeCompressedPublicKeys(fromJacobianPoints: jacobianPoints)
        let singlePublicKeys = try privateKeys.map {
            try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: $0)
        }

        #expect(batchPublicKeys == singlePublicKeys)
    }

    @Test("Forced serial and forced parallel batch derivation return identical ordered results")
    func forcedSerialAndForcedParallelBatchDerivationReturnIdenticalOrderedResults() async throws {
        let privateKeys = (1...1024).map(makePrivateKey)

        let forcedSerialPublicKeys = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys,
                executionMode: .serial
            )
        let forcedParallelPublicKeys = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys,
                executionMode: .parallel
            )

        #expect(forcedSerialPublicKeys == forcedParallelPublicKeys)
    }

    @Test("Automatic batch derivation matches forced parallel results at the tuned thresholds")
    func automaticBatchDerivationMatchesForcedParallelResultsAtTheTunedThresholds() async throws {
        let privateKeys256 = (1...256).map(makePrivateKey)
        let privateKeys1024 = (1...1024).map(makePrivateKey)

        let automaticPublicKeys256 = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys256,
                executionMode: .automatic
            )
        let forcedParallelPublicKeys256 = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys256,
                executionMode: .parallel
            )
        let automaticPublicKeys1024 = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys1024,
                executionMode: .automatic
            )
        let forcedParallelPublicKeys1024 =
            try await StandardsForEfficientCryptography256k1CurveModel.Operation
            .deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys1024,
                executionMode: .parallel
            )

        #expect(automaticPublicKeys256 == forcedParallelPublicKeys256)
        #expect(automaticPublicKeys1024 == forcedParallelPublicKeys1024)
    }

    private func makePrivateKey(_ value: Int) -> Data {
        var privateKey = Data(repeating: 0x00, count: 32)
        let resolvedValue = UInt32(value)
        privateKey[28] = UInt8((resolvedValue >> 24) & 0xff)
        privateKey[29] = UInt8((resolvedValue >> 16) & 0xff)
        privateKey[30] = UInt8((resolvedValue >> 8) & 0xff)
        privateKey[31] = UInt8(resolvedValue & 0xff)
        return privateKey
    }
}
