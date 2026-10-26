// PedersenPrecomputationValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Pedersen commitment precomputation validation")
struct PedersenPrecomputationValidator {
    struct CommitmentCase: Sendable {
        let amount: Int64
        let nonceData: Data
    }

    @Test(
        "Commitments match the independent nonce*G + amount*H ladder formula",
        arguments: [
            CommitmentCase(amount: 0, nonceData: smallNonce(1)),
            CommitmentCase(amount: 1, nonceData: smallNonce(0)),
            CommitmentCase(amount: 1, nonceData: smallNonce(1)),
            CommitmentCase(
                amount: -1,
                nonceData: try! Data(
                    hexadecimal:
                        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
                )
            ),
            CommitmentCase(amount: -10, nonceData: smallNonce(3)),
            CommitmentCase(
                amount: .min,
                nonceData: Data(repeating: 0x7f, count: 32)
            ),
            CommitmentCase(amount: .max, nonceData: smallNonce(7)),
            CommitmentCase(
                amount: 27,
                nonceData: Data(repeating: 0x7f, count: 32)
            )
        ]
    )
    func matchIndependentCommitmentFormula(
        sample: CommitmentCase
    ) throws {
        let nonce = try ScalarModel(
            data32: sample.nonceData,
            requireNonZero: false
        )
        let amountMagnitude = sample.amount.magnitude
        let amountBytes = Data(repeating: 0, count: 24) + Data(
            (0 ..< 8).reversed().map {
                UInt8(truncatingIfNeeded: amountMagnitude >> ($0 * 8))
            }
        )
        let magnitude = try ScalarModel(
            data32: amountBytes,
            requireNonZero: false
        )
        let amountScalar = sample.amount < 0 ? magnitude.negateModN() : magnitude
        let alternatePoint = try PublicKeyParserModel.parsePublicKey(
            Data([0x02]) + Data("CashFusion gives us fungibility.".utf8)
        )
        // Use the direct commitment formula and the independent ladder path,
        // avoiding both cached tables and the (H+G, amount-nonce) decomposition.
        let expected = try #require(
            ScalarMultiplicationModel.mulWithDoubleAndAddLadder(
                nonce,
                ScalarMultiplicationModel.generator
            ).add(
                ScalarMultiplicationModel.mulWithDoubleAndAddLadder(
                    amountScalar,
                    alternatePoint
                )
            ).convertToAffine()
        )
        let actual = try OpalCrypto.Pedersen.Setup().commit(
            amount: sample.amount,
            nonce: .init(rawRepresentation: sample.nonceData)
        )

        #expect(actual.point.uncompressedRepresentation == expected.encodeUncompressed65())
    }

    private static func smallNonce(_ value: UInt8) -> Data {
        Data(repeating: 0, count: 31) + Data([value])
    }
}
