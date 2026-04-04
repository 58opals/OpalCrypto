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

    private func makeScalar(_ value: UInt8) -> Data {
        Data(repeating: 0x00, count: 31) + Data([value])
    }
}

private extension Data {
    init(hexadecimal: String) throws {
        let normalized = hexadecimal.trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalized.count.isMultiple(of: 2) else {
            throw HexadecimalDataError.invalidLength
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(normalized.count / 2)
        var cursor = normalized.startIndex
        while cursor < normalized.endIndex {
            let nextCursor = normalized.index(cursor, offsetBy: 2)
            let pair = normalized[cursor..<nextCursor]
            guard let byte = UInt8(pair, radix: 16) else {
                throw HexadecimalDataError.invalidCharacter
            }
            bytes.append(byte)
            cursor = nextCursor
        }
        self = Data(bytes)
    }
}

private enum HexadecimalDataError: Error {
    case invalidLength
    case invalidCharacter
}
