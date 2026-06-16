// DiagnosticsIntegrationValidator~HashingKeyDerivation.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("Hashing facade records public-safe boundary diagnostics")
    func validateHashingFacadeRecordsPublicSafeBoundaryDiagnostics() throws {
        try withDiagnosticsCapture {
            let payload = Data("diagnostics-hash-payload".utf8)

            let digest = OpalCrypto.Hashing.hash160(payload)

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.hash160Succeeded))
            #expect(record.category == OpalDiagnostics.Category.hashing)
            #expect(record.level == .debug)
            #expect(field("operation", in: record)?.value == "hash")
            #expect(field("algorithm", in: record)?.value == "hash160")
            #expect(field("input_byte_count", in: record)?.value == String(payload.count))
            #expect(field("output_byte_count", in: record)?.value == String(digest.count))
            #expect(record.fields.contains { $0.value.contains("diagnostics-hash-payload") } == false)

            OpalDiagnostics.clearRecentRecords()

            let key = Data("diagnostics-hmac-key".utf8)
            let mac = OpalCrypto.Hashing.hmacSHA256(data: payload, key: key)

            let hmacRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.hmacSHA256Succeeded))
            #expect(hmacRecord.category == OpalDiagnostics.Category.hashing)
            #expect(hmacRecord.level == .debug)
            #expect(field("operation", in: hmacRecord)?.value == "hmac")
            #expect(field("algorithm", in: hmacRecord)?.value == "hmac_sha256")
            #expect(field("input_byte_count", in: hmacRecord)?.value == String(payload.count))
            #expect(field("output_byte_count", in: hmacRecord)?.value == String(mac.count))
            expectPublicField("key_byte_count", in: hmacRecord, equals: String(key.count))
            #expect(field("key", in: hmacRecord) == nil)
            #expect(hmacRecord.fields.contains { $0.value.contains("diagnostics-hash-payload") } == false)
            #expect(hmacRecord.fields.contains { $0.value.contains("diagnostics-hmac-key") } == false)
        }
    }

    @Test("PBKDF2 failures record stable public error codes without password material")
    func validatePBKDF2FailuresRecordStablePublicErrorCodesWithoutPasswordMaterial() throws {
        try withDiagnosticsCapture {
            let password = Data("wallet-password-material".utf8)
            let salt = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8))

            #expect(throws: OpalCrypto.KeyDerivation.Error.self) {
                _ = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                    password: password,
                    salt: salt,
                    iterationCount: 0,
                    derivedKeyLength: 32
                )
            }

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.pbkdf2DeriveFailed))
            #expect(record.category == OpalDiagnostics.Category.keyDerivation)
            #expect(record.level == .error)
            #expect(field("operation", in: record)?.value == "pbkdf2_derive")
            expectPublicField("password_byte_count", in: record, equals: String(password.count))
            #expect(field("salt_byte_count", in: record)?.value == String(salt.rawRepresentation.count))
            #expect(field("iteration_count", in: record)?.value == "0")
            #expect(field("requested_derived_key_byte_count", in: record)?.value == "32")
            #expect(field("has_explicit_derived_key_length", in: record)?.value == "true")
            #expect(field("error_code", in: record)?.value == "invalid_iteration_count")
            #expect(field("password", in: record) == nil)
            #expect(record.fields.contains { $0.value.contains("wallet-password-material") } == false)
        }
    }

    @Test("PBKDF2 default length diagnostics report the effective byte count")
    func validatePBKDF2DefaultLengthDiagnosticsReportEffectiveByteCount() throws {
        try withDiagnosticsCapture {
            let salt = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8))

            let derivedKey = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                password: Data("wallet-password-material".utf8),
                salt: salt,
                iterationCount: 1,
                derivedKeyLength: nil
            )

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.pbkdf2DeriveSucceeded))
            #expect(derivedKey.rawRepresentation.count == 64)
            #expect(record.category == OpalDiagnostics.Category.keyDerivation)
            #expect(record.level == .debug)
            #expect(field("operation", in: record)?.value == "pbkdf2_derive")
            expectPublicField("password_byte_count", in: record, equals: "24")
            expectPublicField("salt_byte_count", in: record, equals: String(salt.rawRepresentation.count))
            expectPublicField("iteration_count", in: record, equals: "1")
            expectPublicField("requested_derived_key_byte_count", in: record, equals: "64")
            expectPublicField("has_explicit_derived_key_length", in: record, equals: "false")
            expectPublicField("output_byte_count", in: record, equals: "64")
            expectPublicField("derived_key_byte_count", in: record, equals: "64")
            #expect(field("password", in: record) == nil)
            #expect(field("salt", in: record) == nil)
            #expect(record.fields.contains { $0.value.contains("wallet-password-material") } == false)
        }
    }
}
