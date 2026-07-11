// DiagnosticsIntegrationValidator~WalletImportFormat.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

extension DiagnosticsIntegrationValidator {
    @Test("WIF parsing does not emit nested private-key parse diagnostics")
    func validateWIFParsingDoesNotEmitNestedPrivateKeyParseDiagnostics() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(17)
            let serialized = OpalCrypto.Key.WIF(privateKey: privateKey).serialize()

            OpalDiagnostics.clearRecentRecords()

            _ = try OpalCrypto.Key.WIF(serialized)

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.wifParseSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: record)?.value == "wif_parse")
            #expect(field("format", in: record)?.value == "wif")
            #expect(field("private_key_byte_count", in: record)?.value == "32")
            #expect(field("private_key_byte_count", in: record)?.privacy == .public)
            #expect(field("is_compressed", in: record)?.value == "true")
            #expect(diagnosticRecord(named: OpalDiagnostics.Event.privateKeyParseSucceeded) == nil)
        }
    }

    @Test("WIF serialization records public-safe private-key length")
    func validateWIFSerializationRecordsPublicSafePrivateKeyLength() throws {
        try withDiagnosticsCapture {
            let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(19)

            _ = OpalCrypto.Key.WIF(privateKey: privateKey, isCompressed: false).serialize()

            let record = try #require(diagnosticRecord(named: OpalDiagnostics.Event.wifSerializeSucceeded))
            #expect(record.category == OpalDiagnostics.Category.key)
            #expect(field("operation", in: record)?.value == "wif_serialize")
            #expect(field("format", in: record)?.value == "wif")
            #expect(field("private_key_byte_count", in: record)?.value == "32")
            #expect(field("private_key_byte_count", in: record)?.privacy == .public)
            #expect(field("is_compressed", in: record)?.value == "false")
            #expect(field("output_character_count", in: record)?.value == "51")
        }
    }
}
