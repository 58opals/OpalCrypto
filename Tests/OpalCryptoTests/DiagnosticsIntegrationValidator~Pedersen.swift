// DiagnosticsIntegrationValidator~Pedersen.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("Pedersen point combination does not emit commitment-parse diagnostics")
    func validatePedersenPointCombinationDoesNotEmitCommitmentParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let alternateBasePrivateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(31)
            let alternateBasePoint = try OpalCrypto.Secp256k1.derivePublicKey(from: alternateBasePrivateKey)
            let setup = try OpalCrypto.Pedersen.Setup(alternateBasePoint: alternateBasePoint)
            let firstCommitment = try setup.commit(
                amount: 4,
                nonce: OpalCrypto.Pedersen.Nonce(rawRepresentation: OpalCryptoTestSupport.makePrivateKey(3))
            )
            let secondCommitment = try setup.commit(
                amount: 9,
                nonce: OpalCrypto.Pedersen.Nonce(rawRepresentation: OpalCryptoTestSupport.makePrivateKey(5))
            )

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Pedersen.Setup.addPoints([
                firstCommitment.point,
                secondCommitment.point
            ])

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.pedersenCombineSucceeded))
            #expect(record.category == OpalDiagnostics.Category.pedersen)
            #expect(field("operation", in: record)?.value == "combine_points")
            #expect(field("point_count", in: record)?.value == "2")
            #expect(field("commitment_byte_count", in: record)?.value == "65")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.pedersenCommitmentParseSucceeded) == nil)
        }
    }

    @Test("Pedersen commit records public-safe provided nonce length")
    func validatePedersenCommitRecordsPublicSafeProvidedNonceLength() throws {
        try withDiagnosticsCapture {
            let alternateBasePrivateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(41)
            let alternateBasePoint = try OpalCrypto.Secp256k1.derivePublicKey(from: alternateBasePrivateKey)
            let setup = try OpalCrypto.Pedersen.Setup(alternateBasePoint: alternateBasePoint)

            OpalDiagnostics.clearRecentRecords()

            _ = try setup.commit(
                amount: 8,
                nonce: OpalCrypto.Pedersen.Nonce(rawRepresentation: OpalCryptoTestSupport.makePrivateKey(7))
            )

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.pedersenCommitSucceeded))
            #expect(record.category == OpalDiagnostics.Category.pedersen)
            #expect(record.level == .debug)
            #expect(field("operation", in: record)?.value == "commit")
            expectPublicField("has_provided_nonce", in: record, equals: "true")
            expectPublicField("nonce_byte_count", in: record, equals: "32")
            expectPublicField("commitment_byte_count", in: record, equals: "65")
            #expect(field("amount", in: record) == nil)
            #expect(field("nonce", in: record) == nil)
            #expect(field("commitment", in: record) == nil)
        }
    }

    @Test("Pedersen nonce parsing records public-safe nonce length")
    func validatePedersenNonceParsingRecordsPublicSafeNonceLength() throws {
        try withDiagnosticsCapture {
            _ = try OpalCrypto.Pedersen.Nonce(
                rawRepresentation: OpalCryptoTestSupport.makePrivateKey(11)
            )

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.pedersenNonceParseSucceeded))
            #expect(record.category == OpalDiagnostics.Category.pedersen)
            #expect(record.level == .debug)
            #expect(field("operation", in: record)?.value == "nonce_parse")
            expectPublicField("input_byte_count", in: record, equals: "32")
            expectPublicField("nonce_byte_count", in: record, equals: "32")
            #expect(field("nonce", in: record) == nil)
        }
    }
}
