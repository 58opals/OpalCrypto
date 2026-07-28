// DiagnosticsIntegrationValidator~CategoryFilter.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("Crypto category filter includes diagnostics subcategories")
    func validateCryptoCategoryFilterIncludesDiagnosticsSubcategories() throws {
        try OpalDiagnostics.withConfiguration(Self.diagnosticsConfiguration) {
            OpalDiagnostics.clearRecentRecords()

            _ = OpalCrypto.Encoding.decodeBase58("0", maximumDecodedByteCount: 32)
            #expect(throws: OpalCrypto.Key.WIF.Error.self) {
                _ = try OpalCrypto.Key.WIF("0")
            }
            OpalDiagnostics.logger(category: .base).record(
                event: "opalcrypto.base.filtered",
                level: .debug
            )

            let events = OpalDiagnostics.recentRecords.map(\.event)
            #expect(events.contains(OpalDiagnostics.Event.base58DecodeFailed))
            #expect(events.contains(OpalDiagnostics.Event.base58CheckDecodeFailed))
            #expect(events.contains(OpalDiagnostics.Event.wifParseFailed))
            #expect(events.contains(OpalDiagnostics.Event(rawValue: "opalcrypto.base.filtered")) == false)

            let base58Record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.base58DecodeFailed))
            #expect(base58Record.category == OpalDiagnostics.Category.encoding)
            #expect(base58Record.level == .error)
            #expect(field("operation", in: base58Record)?.value == "base58_decode")
            #expect(field("format", in: base58Record)?.value == "base58")
            expectPublicField("input_character_count", in: base58Record, equals: "1")
            expectPublicField("error_code", in: base58Record, equals: "invalid_base58")

            let encodingRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.base58CheckDecodeFailed))
            #expect(encodingRecord.category == OpalDiagnostics.Category.encoding)
            #expect(encodingRecord.level == .error)
            #expect(field("operation", in: encodingRecord)?.value == "base58check_decode")
            #expect(field("format", in: encodingRecord)?.value == "base58check")
            expectPublicField("input_character_count", in: encodingRecord, equals: "1")

            let wifRecord = try #require(diagnosticRecord(named: OpalDiagnostics.Event.wifParseFailed))
            #expect(wifRecord.category == OpalDiagnostics.Category.key)
            #expect(wifRecord.level == .error)
            #expect(field("operation", in: wifRecord)?.value == "wif_parse")
            #expect(field("format", in: wifRecord)?.value == "wif")
            expectPublicField("input_character_count", in: wifRecord, equals: "1")
            expectPublicField("error_code", in: wifRecord, equals: "invalid_base58")
            #expect(field("private_key", in: wifRecord) == nil)
        }
    }
}
