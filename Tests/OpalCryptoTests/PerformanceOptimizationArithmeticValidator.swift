// PerformanceOptimizationArithmeticValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Performance optimization arithmetic validation")
struct PerformanceOptimizationArithmeticValidator {
    @Test("Specialized field sqrt and residue helpers preserve the old exponentiation results")
    func specializedFieldSqrtAndResidueHelpersPreserveTheOldExponentiationResults() throws {
        let fieldElement = try FieldElementModel(
            data32: Data([UInt8](repeating: 0x00, count: 31) + [0x04])
        )
        let squareRoot = try #require(fieldElement.sqrt())
        let expectedSquareRoot = fieldElement.pow(exponentBits: FieldPowModel.squareRootExponentBits)

        #expect(squareRoot == expectedSquareRoot)
        #expect(
            fieldElement.isQuadraticResidue
                == (fieldElement.pow(exponentBits: FieldPowModel.legendreExponentBits) == .one)
        )
    }

    @Test("Specialized scalar inversion preserves the old exponentiation result")
    func specializedScalarInversionPreservesTheOldExponentiationResult() throws {
        let scalar = try ScalarModel(
            data32: OpalCryptoTestSupport.makePrivateKey(15),
            requireNonZero: true
        )

        #expect(try scalar.invert() == scalar.pow(exponentBits: ScalarPowModel.inversionExponentBits))
    }

    @Test("Joint generator and cached-key multiplication matches separate multiplication")
    func jointGeneratorAndCachedKeyMultiplicationMatchesSeparateMultiplication() throws {
        let publicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: OpalCryptoTestSupport.makePrivateKey(11)
        )
        let verificationKeyModel = try VerificationKeyModel(publicKeyData: publicKey)
        let generatorScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parseTweakScalar(OpalCryptoTestSupport.makePrivateKey(13), requireNonZero: false)
        let verificationKeyScalar = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parseTweakScalar(OpalCryptoTestSupport.makePrivateKey(17), requireNonZero: false)

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
}
