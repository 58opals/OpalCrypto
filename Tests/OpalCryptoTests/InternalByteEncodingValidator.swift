// InternalByteEncodingValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Internal byte encoding validation")
struct InternalByteEncodingValidator {
    @Test("Byte helpers read offsets relative to sliced Data")
    func byteHelpersReadOffsetsRelativeToSlicedData() {
        let slicedData = Data([0xff, 0x01, 0x02, 0x03, 0x04, 0xee])
            .dropFirst()
            .dropLast()

        #expect(slicedData.uint32BigEndian(at: 0) == 0x0102_0304)
        #expect(slicedData.dataSlice(in: 1..<3) == Data([0x02, 0x03]))
    }
}
