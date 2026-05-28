// PublicAPIPedersenValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API Pedersen validation")
struct PublicAPIPedersenValidator {
    @Test("Pedersen commitments combine like summed amounts and nonces")
    func validatePedersenCommitmentsCombineLikeSummedAmountsAndNonces() throws {
        let setup = try OpalCrypto.Pedersen.Setup(
            alternateBasePoint: alternateBasePoint()
        )
        let commitment0 = try setup.commit(amount: 0, nonce: makeNonce(1))
        let commitment5 = try setup.commit(amount: 5, nonce: makeNonce(2))
        let commitmentMinus10 = try setup.commit(amount: -10, nonce: makeNonce(3))

        let combined = try setup.combine([commitment0, commitment5, commitmentMinus10])
        let manual = try setup.commit(amount: -5, nonce: makeNonce(6))

        #expect(combined == manual)
        #expect(combined.point.compressedRepresentation.count == 33)
        #expect(combined.point.uncompressedRepresentation.count == 65)
        #expect(
            try setup.verify(
                commitment: manual.point,
                amount: -5,
                nonce: makeNonce(6)
            )
        )
        #expect(
            try OpalCrypto.Pedersen.Setup.addPoints(
                [
                    commitment0.point,
                    commitment5.point,
                    commitmentMinus10.point
                ]
            ) == manual.point
        )
    }

    @Test("Pedersen setup rejects an insecure alternate base point")
    func validatePedersenSetupRejectsInsecureAlternateBasePoint() {
        #expect(throws: OpalCrypto.Pedersen.Error.insecureAlternateBasePoint) {
            _ = try OpalCrypto.Pedersen.Setup(
                alternateBasePoint: OpalCrypto.Secp256k1.PublicKey(
                    rawRepresentation: try Data(
                        hexadecimal: "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    )
                )
            )
        }
    }

    @Test("Pedersen setup rejects the generator as an alternate base point")
    func validatePedersenSetupRejectsGeneratorAsAlternateBasePoint() {
        #expect(throws: OpalCrypto.Pedersen.Error.insecureAlternateBasePoint) {
            _ = try OpalCrypto.Pedersen.Setup(
                alternateBasePoint: OpalCrypto.Secp256k1.PublicKey(
                    rawRepresentation: try Data(
                        hexadecimal: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    )
                )
            )
        }
    }

    @Test("Pedersen aggregation preserves valid zero-sum nonces")
    func pedersenAggregationPreservesValidZeroSumNonces() throws {
        let setup = try OpalCrypto.Pedersen.Setup(
            alternateBasePoint: alternateBasePoint()
        )
        let positiveAmountCommitment = try setup.commit(amount: 1, nonce: makeNonce(1))
        let cancelingNonceCommitment = try setup.commit(
            amount: 2,
            nonce: try OpalCrypto.Pedersen.Nonce(
                rawRepresentation: Data(
                    hexadecimal: """
                    fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
                    """
                )
            )
        )

        let expectedCombinedPoint = try OpalCrypto.Pedersen.Setup.addPoints(
            [
                positiveAmountCommitment.point,
                cancelingNonceCommitment.point
            ]
        )
        let combinedCommitment = try setup.combine(
            [positiveAmountCommitment, cancelingNonceCommitment]
        )

        #expect(combinedCommitment.nonce.rawRepresentation == Data(repeating: 0x00, count: 32))
        #expect(combinedCommitment.point == expectedCombinedPoint)
        #expect(
            try setup.verify(
                commitment: combinedCommitment.point,
                amount: 3,
                nonce: combinedCommitment.nonce
            )
        )
    }

    @Test("Pedersen setup rejects commitments created by a different setup")
    func pedersenSetupRejectsCommitmentsCreatedByADifferentSetup() throws {
        let setup = try OpalCrypto.Pedersen.Setup(
            alternateBasePoint: alternateBasePoint()
        )
        let otherSetup = try OpalCrypto.Pedersen.Setup(
            alternateBasePoint: try OpalCrypto.Secp256k1.derivePublicKey(
                from: OpalCryptoTestSupport.makeTypedPrivateKey(21)
            )
        )
        let foreignCommitment = try otherSetup.commit(amount: 1, nonce: makeNonce(1))

        do {
            _ = try setup.combine([foreignCommitment])
            Issue.record("Expected mismatched setup rejection.")
        } catch let error as OpalCrypto.Pedersen.Error {
            #expect(error == .mismatchedSetup)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Pedersen commit reports identity outputs as invalid commitments")
    func pedersenCommitReportsIdentityOutputsAsInvalidCommitments() throws {
        let setup = try OpalCrypto.Pedersen.Setup(
            alternateBasePoint: alternateBasePoint()
        )

        do {
            _ = try setup.commit(
                amount: 0,
                nonce: OpalCrypto.Pedersen.Nonce(rawRepresentation: Data(repeating: 0x00, count: 32))
            )
            Issue.record("Expected identity commitment rejection.")
        } catch let error as OpalCrypto.Pedersen.Error {
            #expect(error == .invalidCommitment)
        } catch {
            Issue.record("Unexpected error type for identity commitment: \(error)")
        }
    }

    private func alternateBasePoint() throws -> OpalCrypto.Secp256k1.PublicKey {
        try OpalCrypto.Secp256k1.PublicKey(
            rawRepresentation: Data([0x02]) + Data("CashFusion gives us fungibility.".utf8)
        )
    }

    private func makeNonce(_ value: UInt8) throws -> OpalCrypto.Pedersen.Nonce {
        try OpalCrypto.Pedersen.Nonce(
            rawRepresentation: Data(repeating: 0x00, count: 31) + Data([value])
        )
    }
}
