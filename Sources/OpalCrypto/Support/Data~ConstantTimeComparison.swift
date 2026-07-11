// Data~ConstantTimeComparison.swift

import Foundation

extension Data {
    func constantTimeEquals(_ other: Data) -> Bool {
        guard count == other.count else {
            return false
        }

        var difference: UInt8 = 0
        // SAFETY: Equal counts guarantee every index is in bounds for both
        // borrowed buffers. Their Data owners remain alive for the nested
        // closures, and neither raw view escapes.
        withUnsafeBytes { (leftBuffer: UnsafeRawBufferPointer) in
            other.withUnsafeBytes { (rightBuffer: UnsafeRawBufferPointer) in
                for index in 0..<count {
                    difference |= leftBuffer[index] ^ rightBuffer[index]
                }
            }
        }
        return difference == 0
    }
}
