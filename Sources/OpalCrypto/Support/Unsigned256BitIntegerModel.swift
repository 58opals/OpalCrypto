// Unsigned256BitIntegerModel.swift

import Foundation

internal struct Unsigned256BitIntegerModel: Sendable {
    internal enum Error: Swift.Error, Equatable {
        case invalidDataLength(expected: Int, actual: Int)
    }

    @usableFromInline var limbs: InlineArray<4, UInt64>

    @inlinable
    init(limbs: InlineArray<4, UInt64>) {
        self.limbs = limbs
    }

    internal init(limbs: [UInt64]) {
        precondition(limbs.count == 4)
        self.limbs = [limbs[0], limbs[1], limbs[2], limbs[3]]
    }

    @usableFromInline static let zero = Unsigned256BitIntegerModel(limbs: .init(repeating: 0))
    @usableFromInline static let one = Unsigned256BitIntegerModel(limbs: [1, 0, 0, 0])

    internal init(data32Bytes: Data) throws {
        guard data32Bytes.count == 32 else {
            throw Error.invalidDataLength(expected: 32, actual: data32Bytes.count)
        }
        var temporaryLimbs: InlineArray<4, UInt64> = .init(repeating: 0)
        data32Bytes.withUnsafeBytes { rawBuffer in
            for index in 0..<4 {
                let word = rawBuffer.loadUnaligned(fromByteOffset: index * 8, as: UInt64.self)
                temporaryLimbs[3 - index] = UInt64(bigEndian: word)
            }
        }
        limbs = temporaryLimbs
    }

    @inlinable
    init(data32: Data) throws {
        try self.init(data32Bytes: data32)
    }

    @inlinable
    internal var data32Bytes: Data {
        var data = Data(count: 32)
        data.withUnsafeMutableBytes { buffer in
            for index in 0..<4 {
                let limb = limbs[3 - index].bigEndian
                buffer.storeBytes(of: limb, toByteOffset: index * 8, as: UInt64.self)
            }
        }
        return data
    }

    @inlinable
    var data32: Data {
        data32Bytes
    }

    @inlinable
    internal func compare(to other: Unsigned256BitIntegerModel) -> ComparisonResult {
        for index in stride(from: 3, through: 0, by: -1) {
            if limbs[index] < other.limbs[index] {
                return .orderedAscending
            }
            if limbs[index] > other.limbs[index] {
                return .orderedDescending
            }
        }
        return .orderedSame
    }

    @inlinable
    internal var isZero: Bool {
        (limbs[0] | limbs[1] | limbs[2] | limbs[3]) == 0
    }

    @inlinable
    internal var isOne: Bool {
        limbs[0] == 1 && limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0
    }

    @inlinable
    internal var isLeastSignificantBitSet: Bool {
        (limbs[0] & 1) == 1
    }

    @inlinable
    internal var mostSignificantBitIndex: Int? {
        for index in stride(from: 3, through: 0, by: -1) {
            let limb = limbs[index]
            if limb != 0 {
                let leadingZeros = limb.leadingZeroBitCount
                return index * 64 + (63 - leadingZeros)
            }
        }
        return nil
    }

    @inlinable
    internal func isBitSet(at index: Int) -> Bool {
        guard index >= 0, index < 256 else {
            return false
        }
        let limbIndex = index / 64
        let bitIndex = index % 64
        return (limbs[limbIndex] >> bitIndex) & 1 == 1
    }
}
