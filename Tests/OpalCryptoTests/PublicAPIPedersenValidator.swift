// PublicAPIPedersenValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API Pedersen validation")
struct PublicAPIPedersenValidator {
    @Test("Pedersen commitments combine like summed amounts and nonces")
    func pedersenCommitmentsCombineLikeSummedAmountsAndNonces() throws {
        let setup = try OpalCrypto.Pedersen.Setup(
            alternateBasePoint: Data([0x02]) + Data("CashFusion gives us fungibility.".utf8)
        )
        let commitment0 = try setup.commit(amount: 0, nonce: makeScalar(1))
        let commitment5 = try setup.commit(amount: 5, nonce: makeScalar(2))
        let commitmentMinus10 = try setup.commit(amount: -10, nonce: makeScalar(3))

        let combined = try setup.combine([commitment0, commitment5, commitmentMinus10])
        let manual = try setup.commit(amount: -5, nonce: makeScalar(6))

        #expect(combined == manual)
        #expect(combined.compressedPoint.count == 33)
        #expect(combined.uncompressedPoint.count == 65)
        #expect(
            try setup.verify(
                commitment: manual.uncompressedPoint,
                amount: -5,
                nonce: makeScalar(6)
            )
        )
        #expect(
            try OpalCrypto.Pedersen.Setup.addPoints(
                [
                    commitment0.uncompressedPoint,
                    commitment5.uncompressedPoint,
                    commitmentMinus10.uncompressedPoint
                ]
            ) == manual.uncompressedPoint
        )
    }

    @Test("Pedersen setup rejects an insecure alternate base point")
    func pedersenSetupRejectsAnInsecureAlternateBasePoint() {
        do {
            _ = try OpalCrypto.Pedersen.Setup(
                alternateBasePoint: try Data(
                    hexadecimal: "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                )
            )
            Issue.record("Expected insecure alternate base point error.")
        } catch let error as OpalCrypto.Pedersen.Error {
            #expect(error == .insecureAlternateBasePoint)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Pedersen aggregation preserves valid zero-sum nonces")
    func pedersenAggregationPreservesValidZeroSumNonces() throws {
        let setup = try OpalCrypto.Pedersen.Setup(
            alternateBasePoint: Data([0x02]) + Data("CashFusion gives us fungibility.".utf8)
        )
        let positiveAmountCommitment = try setup.commit(amount: 1, nonce: makeScalar(1))
        let cancelingNonceCommitment = try setup.commit(
            amount: 2,
            nonce: try Data(
                hexadecimal: """
                fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
                """
            )
        )

        let expectedCombinedPoint = try OpalCrypto.Pedersen.Setup.addPoints(
            [
                positiveAmountCommitment.uncompressedPoint,
                cancelingNonceCommitment.uncompressedPoint
            ]
        )
        let combinedCommitment = try setup.combine(
            [positiveAmountCommitment, cancelingNonceCommitment]
        )

        #expect(combinedCommitment.nonce == Data(repeating: 0x00, count: 32))
        #expect(combinedCommitment.uncompressedPoint == expectedCombinedPoint)
        #expect(
            try setup.verify(
                commitment: combinedCommitment.uncompressedPoint,
                amount: 3,
                nonce: combinedCommitment.nonce
            )
        )
    }

    @Test("Pedersen setup rejects commitments created by a different setup")
    func pedersenSetupRejectsCommitmentsCreatedByADifferentSetup() throws {
        let setup = try OpalCrypto.Pedersen.Setup(
            alternateBasePoint: Data([0x02]) + Data("CashFusion gives us fungibility.".utf8)
        )
        let otherSetup = try OpalCrypto.Pedersen.Setup(
            alternateBasePoint: try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
                from: OpalCryptoTestSupport.makePrivateKey(21)
            )
        )
        let foreignCommitment = try otherSetup.commit(amount: 1, nonce: makeScalar(1))

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
            alternateBasePoint: Data([0x02]) + Data("CashFusion gives us fungibility.".utf8)
        )

        do {
            _ = try setup.commit(amount: 0, nonce: Data(repeating: 0x00, count: 32))
            Issue.record("Expected identity commitment rejection.")
        } catch let error as OpalCrypto.Pedersen.Error {
            #expect(error == .invalidCommitment)
        } catch {
            Issue.record("Unexpected error type for identity commitment: \(error)")
        }
    }

    private func makeScalar(_ value: UInt8) -> Data {
        Data(repeating: 0x00, count: 31) + Data([value])
    }
}
