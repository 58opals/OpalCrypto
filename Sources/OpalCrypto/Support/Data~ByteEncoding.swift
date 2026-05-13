// Data~ByteEncoding.swift

import Foundation

extension Data {
    internal init(bigEndianUInt32 value: UInt32) {
        self = Data()
        reserveCapacity(4)
        appendUInt32BigEndian(value)
    }

    internal mutating func appendUInt32BigEndian(_ value: UInt32) {
        append(contentsOf: [
            UInt8((value >> 24) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff)
        ])
    }

    internal mutating func appendUInt64BigEndian(_ value: UInt64) {
        var bigEndianValue = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndianValue) { rawBuffer in
            append(contentsOf: rawBuffer)
        }
    }

    internal mutating func appendUnsigned256BitIntegerBigEndian(
        _ value: Unsigned256BitIntegerModel
    ) {
        appendUInt64BigEndian(value.limbs[3])
        appendUInt64BigEndian(value.limbs[2])
        appendUInt64BigEndian(value.limbs[1])
        appendUInt64BigEndian(value.limbs[0])
    }

    internal func uint32BigEndian(at offset: Int) -> UInt32 {
        precondition(offset >= 0)
        precondition(offset + 4 <= count)
        let start = index(startIndex, offsetBy: offset)

        return (UInt32(self[start]) << 24)
            | (UInt32(self[index(start, offsetBy: 1)]) << 16)
            | (UInt32(self[index(start, offsetBy: 2)]) << 8)
            | UInt32(self[index(start, offsetBy: 3)])
    }

    internal func dataSlice(in range: Range<Int>) -> Data {
        let lowerBound = index(startIndex, offsetBy: range.lowerBound)
        let upperBound = index(startIndex, offsetBy: range.upperBound)
        return Data(self[lowerBound..<upperBound])
    }
}
