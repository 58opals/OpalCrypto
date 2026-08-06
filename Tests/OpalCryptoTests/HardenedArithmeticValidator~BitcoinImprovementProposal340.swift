// HardenedArithmeticValidator~BitcoinImprovementProposal340.swift

import Foundation
import Testing
@testable import OpalCrypto

extension HardenedArithmeticValidator {
    @Test("Match fixed-schedule BIP340 scalar multiplication with reference arithmetic")
    func matchFixedScheduleBitcoinImprovementProposal340ScalarMultiplicationWithReferenceArithmetic() throws {
        let scalarHexadecimalValues = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"
        ]
        let scalars = try scalarHexadecimalValues.map {
            try ScalarModel(data32: Data(hexadecimal: $0))
        }

        for left in scalars {
            for right in scalars {
                #expect(
                    HardenedScalarArithmeticModel
                        .multiplyModuloCurveOrder(left, right)
                        == left.mulModN(right)
                )
            }
        }
    }

    @Test("Reduce BIP340 hash-sized scalars with fixed-schedule arithmetic")
    func reduceBitcoinImprovementProposal340HashSizedScalarsWithFixedScheduleArithmetic() throws {
        let cases = [
            (
                input: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                expected: "0000000000000000000000000000000000000000000000000000000000000000"
            ),
            (
                input: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                expected: "000000000000000000000000000000014551231950B75FC4402DA1732FC9BEBE"
            )
        ]

        for testCase in cases {
            let reduced = HardenedScalarArithmeticModel
                .reduceData32BytesModuloCurveOrder(
                    try Data(hexadecimal: testCase.input)
                )
            #expect(
                reduced.data32Bytes
                    == (try Data(hexadecimal: testCase.expected))
            )
        }
    }

    @Test("Negate BIP340 scalars with fixed-schedule arithmetic")
    func negateBitcoinImprovementProposal340ScalarsWithFixedScheduleArithmetic() throws {
        let zero = ScalarModel.zero
        let one = ScalarModel.one
        let orderMinusOne = try ScalarModel(
            data32: Data(
                hexadecimal: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"
            )
        )

        #expect(
            HardenedScalarArithmeticModel.negateModuloCurveOrder(zero)
                == zero
        )
        #expect(
            HardenedScalarArithmeticModel.negateModuloCurveOrder(one)
                == orderMinusOne
        )
    }
}
