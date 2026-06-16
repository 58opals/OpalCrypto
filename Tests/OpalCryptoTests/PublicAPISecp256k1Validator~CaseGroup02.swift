// PublicAPISecp256k1Validator~CaseGroup02.swift

import Foundation
import Testing
@testable import OpalCrypto

extension PublicAPISecp256k1Validator {
    @Test("Shared-secret construction normalizes sliced raw input")
    func normalizeSharedSecretConstructionFromSlicedRawInput() throws {
        let sharedSecretData = Data(repeating: 0xAB, count: 32)
        let slicedSharedSecretData = (Data([0xFF]) + sharedSecretData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let sharedSecret = try OpalCrypto.Secp256k1.SharedSecret(
            rawRepresentation: slicedSharedSecretData
        )

        #expect(sharedSecret.rawRepresentation == sharedSecretData)
        #expect(sharedSecret.rawRepresentation.startIndex == 0)
        #expect(sharedSecret.rawRepresentation[0] == 0xAB)
    }

    @Test("Round-trip DER encoding and reject non-canonical DER")
    func roundTripDerEncodingAndRejectNonCanonicalDer() throws {
        let rawSignature = makePrivateKey(1) + makePrivateKey(2)
        let signature = try OpalCrypto.Signature.ECDSA(
            rawRepresentation: rawSignature,
            format: .raw
        )
        let derSignature = try signature.encoded(as: .der)
        #expect(try derSignature.encoded(as: .raw).rawRepresentation == rawSignature)

        let nonCanonicalDer = Data([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02])
        do {
            _ = try OpalCrypto.Signature.ECDSA(rawRepresentation: nonCanonicalDer, format: .der)
            Issue.record("Expected non-canonical DER error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .nonCanonicalDER)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("DER decoding reports canonical oversized integers as invalid signatures")
    func derDecodingReportsCanonicalOversizedIntegersAsInvalidSignatures() {
        let oversizedR = Data([0x01] + Array(repeating: UInt8(0x00), count: 32))
        let validS = Data([0x01])
        let derSignature = Data([0x30, 0x26, 0x02, 0x21]) + oversizedR + Data([0x02, 0x01]) + validS

        do {
            _ = try OpalCrypto.Signature.ECDSA(rawRepresentation: derSignature, format: .der)
            Issue.record("Expected invalid signature error for oversized DER integer.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignature)
        } catch {
            Issue.record("Unexpected error type for oversized DER integer: \(error)")
        }
    }

    @Test("DER decoding reports canonical negative integers as invalid signatures")
    func derDecodingReportsCanonicalNegativeIntegersAsInvalidSignatures() {
        let derSignature = Data([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01])

        do {
            _ = try OpalCrypto.Signature.ECDSA(rawRepresentation: derSignature, format: .der)
            Issue.record("Expected invalid signature error for negative DER integer.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignature)
        } catch {
            Issue.record("Unexpected error type for negative DER integer: \(error)")
        }
    }

    @Test("Normalize and query low-S signatures")
    func normalizeAndQueryLowSSignatures() throws {
        let highSData = StandardsForEfficientCryptography256k1CurveModel.Constant.n
            .subtractWord(1)
            .data32Bytes
        let rawSignature = makePrivateKey(1) + highSData
        let signature = try OpalCrypto.Signature.ECDSA(rawRepresentation: rawSignature, format: .raw)

        #expect(!signature.isLowS)

        let normalizedSignature = try signature.normalizedLowS()
        #expect(normalizedSignature.isLowS)
        #expect(Data(normalizedSignature.rawRepresentation.suffix(32)) == makePrivateKey(1))
    }

    @Test("Batch public-key derivation matches single derivation")
    func batchPublicKeyDerivationMatchesSingleDerivation() async throws {
        let privateKeys = try [1, 2, 3, 4].map {
            try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: makePrivateKey($0))
        }
        let batchPublicKeys = try await OpalCrypto.Secp256k1.derivePublicKeys(
            from: privateKeys
        )
        let singlePublicKeys = try privateKeys.map {
            try OpalCrypto.Secp256k1.derivePublicKey(from: $0)
        }

        #expect(batchPublicKeys == singlePublicKeys)
    }
}
