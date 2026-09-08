// PublicAPIECDSASignatureValidator~Construction.swift

import Foundation
import Testing
import OpalCrypto

extension PublicAPIECDSASignatureValidator {
    @Test("ECDSA raw construction rejects invalid signature scalars")
    func rejectEcdsaRawConstructionWithInvalidSignatureScalars() {
        do {
            _ = try OpalCrypto.Signature.ECDSA(
                rawRepresentation: Data(repeating: 0x00, count: 64),
                format: .raw
            )
            Issue.record("Expected invalid signature error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignature)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("ECDSA signature values normalize sliced raw input")
    func normalizeECDSASignatureValuesFromSlicedRawInput() throws {
        let rawSignature = Data(repeating: 0x00, count: 31) + Data([0x01])
            + Data(repeating: 0x00, count: 31) + Data([0x02])
        let slicedRawSignature = (Data([0xFF]) + rawSignature + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let rawSignatureValue = try OpalCrypto.Signature.ECDSA(
            rawRepresentation: slicedRawSignature,
            format: .raw
        )
        let derSignature = try rawSignatureValue.encoded(as: .der).rawRepresentation
        let slicedDERSignature = (Data([0xFF]) + derSignature + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let derSignatureValue = try OpalCrypto.Signature.ECDSA(
            rawRepresentation: slicedDERSignature,
            format: .der
        )

        #expect(rawSignatureValue.rawRepresentation == rawSignature)
        #expect(rawSignatureValue.rawRepresentation.startIndex == 0)
        #expect(rawSignatureValue.rawRepresentation[0] == 0x00)
        #expect(derSignatureValue.rawRepresentation == derSignature)
        #expect(derSignatureValue.rawRepresentation.startIndex == 0)
        #expect(try derSignatureValue.encoded(as: .raw).rawRepresentation == rawSignature)
    }


}
