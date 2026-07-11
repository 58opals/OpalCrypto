// OpalCryptoBenchmarks.MetalValidation+DeterministicGenerator.swift

import Foundation

extension OpalCryptoBenchmarks.MetalValidation {
    struct DeterministicGenerator {
        private static let fieldModulus: Data = {
            var bytes = Data(repeating: 0xff, count: 32)
            bytes[28] = 0xfe
            bytes[29] = 0xff
            bytes[30] = 0xfc
            bytes[31] = 0x2f
            return bytes
        }()

        var state: UInt64

        mutating func nextCanonicalFieldBytes() -> Data {
            while true {
                var bytes = Data()
                bytes.reserveCapacity(32)
                for _ in 0..<4 {
                    let word = next()
                    for shift in stride(from: 56, through: 0, by: -8) {
                        bytes.append(UInt8(truncatingIfNeeded: word >> UInt64(shift)))
                    }
                }
                if bytes.lexicographicallyPrecedes(Self.fieldModulus) {
                    return bytes
                }
            }
        }

        private mutating func next() -> UInt64 {
            state ^= state << 13
            state ^= state >> 7
            state ^= state << 17
            return state
        }
    }
}
