// Data+ByteEncoding.swift

import Foundation

extension Data {
    internal mutating func appendUInt32BigEndian(_ value: UInt32) {
        append(contentsOf: [
            UInt8((value >> 24) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff)
        ])
    }

    internal func uint32BigEndian(at offset: Int) -> UInt32 {
        precondition(offset >= 0)
        precondition(offset + 4 <= count)

        return (UInt32(self[offset]) << 24)
            | (UInt32(self[offset + 1]) << 16)
            | (UInt32(self[offset + 2]) << 8)
            | UInt32(self[offset + 3])
    }

    internal func dataSlice(in range: Range<Int>) -> Data {
        Data(self[range])
    }
}
