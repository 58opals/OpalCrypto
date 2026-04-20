// Data~ConstantTimeComparison.swift

import Foundation

extension Data {
    func constantTimeEquals(_ other: Data) -> Bool {
        guard count == other.count else {
            return false
        }

        var difference: UInt8 = 0
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
