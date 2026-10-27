// StandardsResourceProvenanceValidator.swift

import CryptoKit
import Foundation
@testable import OpalCrypto
import Testing

@Suite("Standards resource provenance")
struct StandardsResourceProvenanceValidator {
    @Test("Preserve the pinned BIP-39 resource bytes", arguments: [
        ("english", "ce1862ac6bcffa1dd20aad858380e51e66e949ea",
         "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"),
        ("korean", "2880981dc3460801a4f38120a79f290206612942",
         "9e95f86c167de88f450f0aaf89e87f6624a57f973c67b516e338e8e8b8897f60")
    ])
    func preservePinnedWordListBytes(
        resourceName: String,
        revision: String,
        expectedSHA256: String
    ) throws {
        let url = try #require(Bundle.module.url(forResource: resourceName, withExtension: "txt"))
        let bytes = try Data(contentsOf: url)
        let sourceURL = "https://github.com/bitcoin/bips/blob/" + revision
            + "/bip-0039/" + resourceName + ".txt"
        let notice = try noticeText()

        #expect(sha256(bytes) == expectedSHA256)
        #expect(notice.contains(sourceURL))
        #expect(notice.contains(expectedSHA256))
    }

    @Test("Preserve the BIP-340 subset derived from the pinned published CSV")
    func preservePinnedBIP340VectorData() throws {
        let records = BitcoinImprovementProposal340VectorData.records
        #expect(records.map(\.index) == Array(0...14))

        // CSV columns 0...6, omitting comments and the header, with one LF per row.
        // This digest was checked against the complete upstream CSV whose hash is below.
        let rows = records.map { record in
            [
                String(record.index), record.secretKeyHexadecimal ?? "",
                record.publicKeyHexadecimal, record.auxiliaryRandomnessHexadecimal ?? "",
                record.digestHexadecimal, record.signatureHexadecimal,
                record.isValid ? "TRUE" : "FALSE"
            ].joined(separator: ",")
        }.joined(separator: "\n") + "\n"
        let subsetSHA256 = "b50645731f7a5735194711fab5b9e21942575d9137fada5848c7f65d36fb5a02"
        #expect(sha256(Data(rows.utf8)) == subsetSHA256)

        let notice = try noticeText()
        #expect(notice.contains(
            "https://github.com/bitcoin/bips/blob/93f161194fbaed12c44f5e2a0c1d4f2b1b317cb0/bip-0340/test-vectors.csv"
        ))
        #expect(notice.contains("34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d"))
        #expect(notice.contains(subsetSHA256))
    }

    private func noticeText() throws -> String {
        let url = URL(filePath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appending(path: "docs/standards-data-notices.md")
        return try String(contentsOf: url, encoding: .utf8)
    }

    private func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
