// HardenedArithmeticValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Hardened arithmetic validation")
struct HardenedArithmeticValidator {
    @Test("Hardened field arithmetic matches the reference field model")
    func hardenedFieldArithmeticMatchesReferenceFieldModel() throws {
        var values = try [
            "00",
            "01",
            "02",
            "07",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ].map { value -> FieldElementModel in
            let padded = String(repeating: "0", count: 64 - value.count) + value
            return try FieldElementModel(data32: Data(hexadecimal: padded))
        }
        values += try (0..<24).map {
            try FieldElementModel(
                data32: deterministicData32(seed: UInt64($0))
            )
        }

        for left in values {
            let hardenedLeft = HardenedFieldElementModel(left)
            for right in values {
                let hardenedRight = HardenedFieldElementModel(right)
                #expect(
                    hardenedLeft.add(hardenedRight).data32Bytes
                        == left.add(right).data32Bytes
                )
                #expect(
                    hardenedLeft.sub(hardenedRight).data32Bytes
                        == left.sub(right).data32Bytes
                )
                #expect(
                    hardenedLeft.mul(hardenedRight).data32Bytes
                        == left.mul(right).data32Bytes
                )
            }
        }

        for value in values.dropFirst() {
            #expect(
                HardenedFieldElementModel(value).invert().data32Bytes
                    == value.invert().data32Bytes
            )
        }
    }

    @Test("Hardened scalar addition matches the reference scalar model")
    func hardenedScalarAdditionMatchesReferenceScalarModel() throws {
        var values = try [
            "00",
            "01",
            "02",
            "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        ].map { value -> ScalarModel in
            let padded = String(repeating: "0", count: 64 - value.count) + value
            return try ScalarModel(data32: Data(hexadecimal: padded))
        }
        values += try (24..<48).map {
            try ScalarModel(
                data32: deterministicData32(seed: UInt64($0))
            )
        }

        for left in values {
            for right in values {
                #expect(
                    HardenedScalarArithmeticModel
                        .addModN(left, right)
                        .data32Bytes
                        == left.addModN(right).data32Bytes
                )
            }
        }
    }

    @Test("Complete point formulas match the reference point model")
    func completePointFormulasMatchReferencePointModel() throws {
        let generator = ScalarMultiplicationModel.generator
        let completeGenerator = CompleteProjectivePointModel(
            affinePoint: generator
        )
        #expect(
            completeGenerator
                .add(.infinity)
                .affinePoint
                == generator
        )
        #expect(
            CompleteProjectivePointModel.infinity
                .add(completeGenerator)
                .affinePoint
                == generator
        )
        #expect(
            completeGenerator
                .add(
                    CompleteProjectivePointModel(
                        affinePoint: generator.negate()
                    )
                )
                .affinePoint
                == nil
        )

        let expectedDouble = try #require(
            JacobianPointModel(affine: generator).double().convertXToAffine()
        )
        #expect(
            completeGenerator.double().affineXCoordinateData32Bytes
                == expectedDouble.data32Bytes
        )
        #expect(
            completeGenerator
                .add(completeGenerator)
                .affineXCoordinateData32Bytes
                == expectedDouble.data32Bytes
        )

        let twiceGenerator = try #require(
            JacobianPointModel(affine: generator).double().convertToAffine()
        )
        let expectedTriple = try #require(
            JacobianPointModel(affine: twiceGenerator)
                .addAffine(generator)
                .convertXToAffine()
        )
        #expect(
            CompleteProjectivePointModel(affinePoint: twiceGenerator)
                .add(completeGenerator)
                .affineXCoordinateData32Bytes
                == expectedTriple.data32Bytes
        )
    }

    @Test("Hardened scalar multiplication matches reference points")
    func hardenedScalarMultiplicationMatchesReferencePoints() throws {
        let cases: [(scalar: Int, pointScalar: Int)] = [
            (1, 1),
            (2, 37),
            (7, 13),
            (13, 37),
            (37, 7),
            (255, 2)
        ]

        #expect(
            HardenedScalarMultiplicationModel
                .multiply(.zero, by: ScalarMultiplicationModel.generator)
                .affinePoint
                == nil
        )

        for testCase in cases {
            let scalar = try ScalarModel(
                data32: OpalCryptoTestSupport.makePrivateKey(testCase.scalar)
            )
            let pointScalar = try ScalarModel(
                data32:
                    OpalCryptoTestSupport.makePrivateKey(
                        testCase.pointScalar
                    )
            )
            let point = try #require(
                ScalarMultiplicationModel
                    .mulG(pointScalar)
                    .convertToAffine()
            )
            let reference = try #require(
                ScalarMultiplicationModel
                    .mul(scalar, point)
                    .convertToAffine()
            )

            #expect(
                HardenedScalarMultiplicationModel
                    .multiply(scalar, by: point)
                    .affinePoint
                    == reference
            )
        }
    }

    @Test("Hardened scalar multiplication covers every scalar limb")
    func hardenedScalarMultiplicationCoversEveryScalarLimb() throws {
        let cases: [(scalarHex: String, pointScalar: Int)] = [
            (
                "0000000000000000000000000000000000000000000000010000000000000001",
                37
            ),
            (
                "0000000000000000000000000000000080000000000000000123456789abcdef",
                255
            ),
            (
                "00000000000000000000000000000001deadbeefcafebabe0123456789abcdef",
                13
            ),
            (
                "000000000000000080000000000000000123456789abcdeffedcba9876543210",
                7
            ),
            (
                "80000000000000000123456789abcdeffedcba98765432100f0e0d0c0b0a0908",
                2
            ),
            (
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                37
            )
        ]

        for testCase in cases {
            let scalar = try ScalarModel(
                data32: Data(hexadecimal: testCase.scalarHex)
            )
            let pointScalar = try ScalarModel(
                data32:
                    OpalCryptoTestSupport.makePrivateKey(
                        testCase.pointScalar
                    )
            )
            let point = try #require(
                ScalarMultiplicationModel
                    .mulG(pointScalar)
                    .convertToAffine()
            )
            let reference = try #require(
                ScalarMultiplicationModel
                    .mul(scalar, point)
                    .convertToAffine()
            )
            let hardened = HardenedScalarMultiplicationModel
                .multiply(scalar, by: point)
                .affinePoint

            #expect(
                hardened == reference,
                "scalar \(testCase.scalarHex), point scalar \(testCase.pointScalar)"
            )
        }
    }

    @Test("Long complete-projective chains match reference arithmetic")
    func longCompleteProjectiveChainsMatchReferenceArithmetic() throws {
        let generator = ScalarMultiplicationModel.generator
        let twiceGenerator = try #require(
            JacobianPointModel(affine: generator)
                .double()
                .convertToAffine()
        )
        var completeLeft = CompleteProjectivePointModel(
            affinePoint: generator
        )
        var completeRight = CompleteProjectivePointModel(
            affinePoint: twiceGenerator
        )
        var referenceLeft = JacobianPointModel(affine: generator)
        var referenceRight = JacobianPointModel(affine: twiceGenerator)

        for round in 0..<192 {
            let nextCompleteLeft = completeLeft.double().add(completeRight)
            let nextCompleteRight = completeRight.double().add(completeLeft)
            let nextReferenceLeft = referenceLeft.double().add(referenceRight)
            let nextReferenceRight = referenceRight.double().add(referenceLeft)

            completeLeft = nextCompleteLeft
            completeRight = nextCompleteRight
            referenceLeft = nextReferenceLeft
            referenceRight = nextReferenceRight

            if round.isMultiple(of: 16) {
                #expect(
                    completeLeft.affinePoint
                        == referenceLeft.convertToAffine(),
                    "left projective chain diverged at round \(round)"
                )
                #expect(
                    completeRight.affinePoint
                        == referenceRight.convertToAffine(),
                    "right projective chain diverged at round \(round)"
                )
            }
        }

        #expect(
            completeLeft.affinePoint == referenceLeft.convertToAffine()
        )
        #expect(
            completeRight.affinePoint == referenceRight.convertToAffine()
        )
    }

    private func deterministicData32(seed: UInt64) -> Data {
        var state = seed ^ 0xD1B5_4A32_D192_ED03
        var data = Data()
        data.reserveCapacity(32)
        for _ in 0..<4 {
            state = state &* 0x9E37_79B9_7F4A_7C15
                &+ 0xBF58_476D_1CE4_E5B9
            var bigEndianState = state.bigEndian
            withUnsafeBytes(of: &bigEndianState) {
                data.append(contentsOf: $0)
            }
        }
        data[0] = seed.isMultiple(of: 2)
            ? data[0] & 0x7F
            : 0xFE
        return data
    }
}
