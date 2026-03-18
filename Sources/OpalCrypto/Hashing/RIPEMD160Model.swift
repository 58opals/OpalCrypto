// RIPEMD160Model.swift

import Foundation

struct RIPEMD160Model {
    var hashState: (UInt32, UInt32, UInt32, UInt32, UInt32)
    var messageBuffer: Data
    var processedBytesCount: Int64 // Total number of bytes processed.

    init() {
        hashState = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)
        messageBuffer = Data()
        processedBytesCount = 0
    }
}
