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

        #expect(
            FieldElementModel.three.isQuadraticResidue
                == (FieldElementModel.three.pow(exponentBits: FieldPowModel.legendreExponentBits) == .one)
        )
    }

    @Test("Field residue predicate treats zero as a residue")
    func fieldResiduePredicateTreatsZeroAsAResidue() {
        #expect(FieldElementModel.zero.isQuadraticResidue)
        #expect(FieldElementModel.zero.sqrt() == .zero)
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
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(
            from: OpalCryptoTestSupport.makeTypedPrivateKey(11)
        )
        let verificationKeyModel = try VerificationKeyModel(
            publicKeyData: publicKey.rawRepresentation
        )
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

    @Test(
        "Fixed windowed non-adjacent form digits match the array algorithm",
        arguments: WindowedNonAdjacentFormCase.allCases
    )
    func fixedWindowedNonAdjacentFormDigitsMatchTheArrayAlgorithm(
        testCase: WindowedNonAdjacentFormCase
    ) throws {
        let scalar = try testCase.scalar()
        expectFixedDigitsMatchReference(scalar, width: 5)
        expectFixedDigitsMatchReference(scalar, width: 6)
    }

    private func expectFixedDigitsMatchReference(
        _ scalar: SignedScalar128Model,
        width: Int
    ) {
        let actual = SignedScalar128Model
            .makeWindowedNonAdjacentForm(scalar, width: width)
            .values
        #expect(actual == referenceWindowedNonAdjacentForm(scalar, width: width))
    }

    private func referenceWindowedNonAdjacentForm(
        _ scalar: SignedScalar128Model,
        width: Int
    ) -> [Int8] {
        guard !scalar.isZero else {
            return [0]
        }

        let windowMask = UInt64((1 << width) - 1)
        let windowHalf = Int64(1 << (width - 1))
        let windowFull = Int64(1 << width)

        var magnitude = scalar.magnitude
        var digits: [Int8] = .init()
        digits.reserveCapacity(130)

        while !magnitude.isZero {
            var digit: Int64 = 0
            if (magnitude.limbs[0] & 1) == 1 {
                let lowBits = Int64(magnitude.limbs[0] & windowMask)
                digit = lowBits
                if digit > windowHalf {
                    digit -= windowFull
                }
                if digit < 0 {
                    magnitude = magnitude.addWord(UInt64(-digit))
                } else {
                    magnitude = magnitude.subtractWord(UInt64(digit))
                }
            }

            digits.append(scalar.isNegative ? Int8(-digit) : Int8(digit))
            magnitude = magnitude.shiftRightOneBit()
        }

        return digits
    }

}
