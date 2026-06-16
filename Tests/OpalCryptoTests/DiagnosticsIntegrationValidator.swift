// DiagnosticsIntegrationValidator.swift

import Foundation
import OpalDiagnostics
import Testing
@testable import OpalCrypto

@Suite(.serialized)
struct DiagnosticsIntegrationValidator {
    static let diagnosticsConfiguration = OpalDiagnostics.Configuration(
        minimumLevel: .debug,
        categoryFilter: .enabledIncludingSubcategories([OpalDiagnostics.Category.crypto]),
        bufferPolicy: .enabled(capacity: 1_000)
    )

    func withDiagnosticsCapture<Success>(_ operation: () throws -> Success) rethrows -> Success {
        try OpalDiagnostics.withConfiguration(Self.diagnosticsConfiguration) {
            OpalDiagnostics.clearRecentRecords()
            return try operation()
        }
    }

    func withDiagnosticsCapture<Success>(_ operation: () async throws -> Success) async rethrows -> Success {
        try await OpalDiagnostics.withConfiguration(Self.diagnosticsConfiguration) {
            OpalDiagnostics.clearRecentRecords()
            return try await operation()
        }
    }

    func diagnosticRecord(
        named event: OpalDiagnostics.Event
    ) -> OpalDiagnostics.Record? {
        OpalDiagnostics.recentRecords(matching: .init(event: event)).first
    }

    func field(
        _ name: String,
        in record: OpalDiagnostics.Record
    ) -> OpalDiagnostics.Field? {
        record.fields.first { $0.name == name }
    }

    func expectPublicField(
        _ name: String,
        in record: OpalDiagnostics.Record,
        equals expectedValue: String
    ) {
        let diagnosticField = field(name, in: record)
        #expect(diagnosticField?.value == expectedValue)
        #expect(diagnosticField?.privacy == .public)
    }

    func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
