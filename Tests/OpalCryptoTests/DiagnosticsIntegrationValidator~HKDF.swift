// DiagnosticsIntegrationValidator~HKDF.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("HKDF diagnostics retain public lengths and redact key material")
    func validateHKDFDiagnosticsRedactKeyMaterial() throws {
        try withDiagnosticsCapture {
            let inputKeyMaterial = Data("hkdf-input-key-material".utf8)
            let salt = Data("hkdf-independent-salt".utf8)
            let information = Data("hkdf-context-information".utf8)
            let derivedKey = try OpalCrypto.KeyDerivation.deriveHKDFSHA256Key(
                inputKeyMaterial: inputKeyMaterial,
                salt: salt,
                information: information,
                outputByteCount: 32
            )
            let success = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.hkdfSHA256DeriveSucceeded)
            )
            #expect(success.category == OpalDiagnostics.Category.keyDerivation)
            expectPublicField("operation", in: success, equals: "hkdf_sha256_derive")
            expectPublicField(
                "input_key_material_byte_count", in: success,
                equals: String(inputKeyMaterial.count)
            )
            expectPublicField("salt_byte_count", in: success, equals: String(salt.count))
            expectPublicField(
                "information_byte_count", in: success,
                equals: String(information.count)
            )
            expectPublicField("requested_derived_key_byte_count", in: success, equals: "32")
            expectPublicField("derived_key_byte_count", in: success, equals: "32")
            expectPublicField("output_byte_count", in: success, equals: "32")

            #expect(
                throws: OpalCrypto.KeyDerivation.Error.invalidDerivedKeyLength(actual: 0)
            ) {
                _ = try OpalCrypto.KeyDerivation.deriveHKDFSHA256Key(
                    inputKeyMaterial: inputKeyMaterial,
                    salt: salt,
                    information: information,
                    outputByteCount: 0
                )
            }
            let failure = try #require(
                diagnosticRecord(named: OpalDiagnostics.Event.hkdfSHA256DeriveFailed)
            )
            expectPublicField("error_code", in: failure, equals: "invalid_derived_key_length")
            expectPublicField("requested_derived_key_byte_count", in: failure, equals: "0")

            for record in [success, failure] {
                for forbiddenName in ["input_key_material", "salt", "information", "derived_key"] {
                    #expect(field(forbiddenName, in: record) == nil)
                }
                for forbiddenValue in [
                    String(decoding: inputKeyMaterial, as: UTF8.self),
                    String(decoding: salt, as: UTF8.self),
                    String(decoding: information, as: UTF8.self),
                    hex(derivedKey.rawRepresentation)
                ] {
                    #expect(record.fields.contains { $0.value.contains(forbiddenValue) } == false)
                }
            }
            #expect(derivedKey.description == "OpalCrypto.KeyDerivation.DerivedKey(redacted, byteCount: 32)")
            #expect(derivedKey.debugDescription == derivedKey.description)
        }
    }
}
