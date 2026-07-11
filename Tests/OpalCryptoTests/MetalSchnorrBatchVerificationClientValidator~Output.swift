// MetalSchnorrBatchVerificationClientValidator~Output.swift

import Testing
@testable import OpalCrypto

extension MetalSchnorrBatchVerificationClientValidator {
    @Test("Output decoding preserves binary result order")
    func preserveBinaryOutputOrderWhenDecoding() throws {
        let outputWords: [UInt32] = [1, 0, 1, 1, 0]
        let results = try outputWords.withUnsafeBufferPointer {
            try MetalSchnorrBatchVerificationClient.decodeOutputWords($0)
        }

        #expect(results == [true, false, true, true, false])
    }

    @Test("Output decoding rejects every nonbinary word")
    func rejectNonbinaryOutputWords() {
        for invalidWord in [UInt32(2), 3, UInt32.max] {
            #expect(throws: MetalSchnorrBatchVerificationError.invalidOutput) {
                try [UInt32(0), invalidWord, 1].withUnsafeBufferPointer {
                    try MetalSchnorrBatchVerificationClient.decodeOutputWords($0)
                }
            }
        }
    }
}
