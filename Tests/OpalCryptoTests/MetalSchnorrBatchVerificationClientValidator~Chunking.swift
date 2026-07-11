// MetalSchnorrBatchVerificationClientValidator~Chunking.swift

import Testing
@testable import OpalCrypto

extension MetalSchnorrBatchVerificationClientValidator {
    @Test("Metal chunk ranges preserve every production boundary")
    func preserveMetalChunkRangeBoundaries() {
        #expect(SchnorrBatchVerificationOperation.metalChunkRanges(recordCount: 0) == [])
        #expect(
            SchnorrBatchVerificationOperation.metalChunkRanges(recordCount: 4_095)
                == [0..<4_095]
        )
        #expect(
            SchnorrBatchVerificationOperation.metalChunkRanges(recordCount: 4_096)
                == [0..<4_096]
        )
        #expect(
            SchnorrBatchVerificationOperation.metalChunkRanges(recordCount: 8_191)
                == [0..<8_191]
        )
        #expect(
            SchnorrBatchVerificationOperation.metalChunkRanges(recordCount: 8_192)
                == [0..<8_192]
        )
        #expect(
            SchnorrBatchVerificationOperation.metalChunkRanges(recordCount: 8_193)
                == [0..<8_192, 8_192..<8_193]
        )
        #expect(
            SchnorrBatchVerificationOperation.metalChunkRanges(recordCount: 16_385)
                == [0..<8_192, 8_192..<16_384, 16_384..<16_385]
        )
    }
}
