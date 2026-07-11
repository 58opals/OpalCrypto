// Unsigned512BitIntegerModel.swift

import Foundation

internal struct Unsigned512BitIntegerModel: Sendable {

    @usableFromInline var limbs: InlineArray<8, UInt64>

    @inlinable
    init(limbs: InlineArray<8, UInt64>) {
        self.limbs = limbs
    }

    internal init(limbs: [UInt64]) {
        precondition(limbs.count == 8)
        self.limbs = [
            limbs[0], limbs[1], limbs[2], limbs[3],
            limbs[4], limbs[5], limbs[6], limbs[7]
        ]
    }

    internal init(data64Bytes: Data) throws {
        guard data64Bytes.count == 64 else {
            throw Error.invalidDataLength(expected: 64, actual: data64Bytes.count)
        }
        var temporaryLimbs: InlineArray<8, UInt64> = .init(repeating: 0)
        data64Bytes.withUnsafeBytes { rawBuffer in
            // SAFETY: The length guard provides eight complete eight-byte
            // words. loadUnaligned removes alignment requirements, offsets
            // 0...56 stay in bounds, and the borrowed storage does not escape.
            for index in 0..<8 {
                let word = rawBuffer.loadUnaligned(fromByteOffset: index * 8, as: UInt64.self)
                temporaryLimbs[7 - index] = UInt64(bigEndian: word)
            }
        }
        limbs = temporaryLimbs
    }

    @inlinable
    init(data64: Data) throws {
        try self.init(data64Bytes: data64)
    }

    @inlinable
    internal var data64Bytes: Data {
        var data = Data(count: 64)
        data.withUnsafeMutableBytes { buffer in
            // SAFETY: Data owns exactly 64 writable bytes for this closure.
            // Eight raw eight-byte stores at offsets 0...56 stay within that
            // storage and initialize the complete allocation without escaping.
            for index in 0..<8 {
                let limb = limbs[7 - index].bigEndian
                buffer.storeBytes(of: limb, toByteOffset: index * 8, as: UInt64.self)
            }
        }
        return data
    }

    @inlinable
    var data64: Data {
        data64Bytes
    }

    @inlinable
    internal var isZero: Bool {
        (limbs[0] | limbs[1] | limbs[2] | limbs[3] |
         limbs[4] | limbs[5] | limbs[6] | limbs[7]) == 0
    }
}
