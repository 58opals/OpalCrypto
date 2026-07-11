// MetalWindowedNonAdjacentFormLayoutValidator.swift

import Testing
@testable import OpalCrypto

@Suite("Metal WNAF layout validation")
struct MetalWindowedNonAdjacentFormLayoutValidator {
    @Test("Packed component/index layout round trips", arguments: [0, 1, 3, 17])
    func packedComponentIndexLayoutRoundTrips(recordCount: Int) {
        let recordMajorDigits = makeRecordMajorDigits(recordCount: recordCount)

        let packedDigits = PerformanceBenchmarkOperations
            .packMetalWindowedNonAdjacentFormDigits(
                recordMajorDigits,
                recordCount: recordCount
            )
        let unpackedDigits = PerformanceBenchmarkOperations
            .unpackMetalWindowedNonAdjacentFormDigits(
                packedDigits,
                recordCount: recordCount
            )

        #expect(unpackedDigits == recordMajorDigits)
    }

    @Test("Adjacent records occupy adjacent packed bytes")
    func adjacentRecordsOccupyAdjacentPackedBytes() {
        let recordCount = 4
        let recordMajorDigits = makeRecordMajorDigits(recordCount: recordCount)
        let packedDigits = PerformanceBenchmarkOperations
            .packMetalWindowedNonAdjacentFormDigits(
                recordMajorDigits,
                recordCount: recordCount
            )

        for component in 0..<PerformanceBenchmarkOperations
            .metalWindowedNonAdjacentFormComponentCount
        {
            for digitIndex in 0..<PerformanceBenchmarkOperations
                .metalWindowedNonAdjacentFormDigitCount
            {
                let packedBase = PerformanceBenchmarkOperations
                    .metalWindowedNonAdjacentFormPackedDigitOffset(
                        recordIndex: 0,
                        component: component,
                        digitIndex: digitIndex,
                        recordCount: recordCount
                    )
                for recordIndex in 0..<recordCount {
                    let sourceIndex = recordIndex * digitsPerRecord
                        + component
                            * PerformanceBenchmarkOperations
                                .metalWindowedNonAdjacentFormDigitCount
                        + digitIndex
                    #expect(
                        packedDigits[packedBase + recordIndex]
                            == recordMajorDigits[sourceIndex]
                    )
                }
            }
        }
    }

    private var digitsPerRecord: Int {
        PerformanceBenchmarkOperations.metalWindowedNonAdjacentFormComponentCount
            * PerformanceBenchmarkOperations.metalWindowedNonAdjacentFormDigitCount
    }

    private func makeRecordMajorDigits(recordCount: Int) -> [Int8] {
        (0..<(recordCount * digitsPerRecord)).map { index in
            Int8(index % 127 - 63)
        }
    }
}
