// RSABSSAInteger.swift

import Foundation

/// Variable-width unsigned arithmetic used only for RFC 9474 client blinding.
///
/// Private-key RSA operations remain in Security.framework. This type handles
/// the public-modulus multiplication and inversion that SecKey does not expose.
internal struct RSABSSAInteger: Comparable, Sendable {
    private var words: [UInt32]

    internal static let zero = Self(words: [])
    internal static let one = Self(words: [1])

    internal init(bigEndianRepresentation: Data) {
        var resolvedWords: [UInt32] = []
        resolvedWords.reserveCapacity((bigEndianRepresentation.count + 3) / 4)

        var end = bigEndianRepresentation.endIndex
        while end > bigEndianRepresentation.startIndex {
            let start = bigEndianRepresentation.index(
                end,
                offsetBy: -4,
                limitedBy: bigEndianRepresentation.startIndex
            ) ?? bigEndianRepresentation.startIndex
            var word: UInt32 = 0
            for byte in bigEndianRepresentation[start ..< end] {
                word = (word << 8) | UInt32(byte)
            }
            resolvedWords.append(word)
            end = start
        }

        self.init(words: resolvedWords)
    }

    internal var isZero: Bool { words.isEmpty }
    internal var isOne: Bool { words.count == 1 && words[0] == 1 }
    internal var isEven: Bool { words.first.map { $0 & 1 == 0 } ?? true }

    internal var bitCount: Int {
        guard let mostSignificantWord = words.last else { return 0 }
        return (words.count - 1) * 32
            + (UInt32.bitWidth - mostSignificantWord.leadingZeroBitCount)
    }

    internal func isBitSet(at index: Int) -> Bool {
        guard index >= 0 else { return false }
        let wordIndex = index / 32
        guard wordIndex < words.count else { return false }
        return words[wordIndex] & (UInt32(1) << UInt32(index % 32)) != 0
    }

    internal func bigEndianRepresentation(paddedTo byteCount: Int) -> Data? {
        guard byteCount >= 0 else { return nil }
        let minimalRepresentation = bigEndianRepresentation
        guard minimalRepresentation.count <= byteCount else { return nil }

        var result = Data(
            repeating: 0,
            count: byteCount - minimalRepresentation.count
        )
        result.append(minimalRepresentation)
        return result
    }

    internal static func < (lhs: Self, rhs: Self) -> Bool {
        guard lhs.words.count == rhs.words.count else {
            return lhs.words.count < rhs.words.count
        }
        for index in lhs.words.indices.reversed()
        where lhs.words[index] != rhs.words[index] {
            return lhs.words[index] < rhs.words[index]
        }
        return false
    }

    internal func adding(_ other: Self) -> Self {
        let resultCount = max(words.count, other.words.count)
        var result = [UInt32](repeating: 0, count: resultCount)
        var carry: UInt64 = 0

        for index in 0 ..< resultCount {
            let left = index < words.count ? UInt64(words[index]) : 0
            let right = index < other.words.count ? UInt64(other.words[index]) : 0
            let sum = left + right + carry
            result[index] = UInt32(truncatingIfNeeded: sum)
            carry = sum >> 32
        }
        if carry != 0 {
            result.append(UInt32(carry))
        }
        return Self(words: result)
    }

    internal func subtracting(_ other: Self) -> Self {
        precondition(self >= other)
        var result = words
        var borrow: UInt32 = 0

        for index in result.indices {
            let right = index < other.words.count ? other.words[index] : 0
            let first = result[index].subtractingReportingOverflow(right)
            let second = first.partialValue.subtractingReportingOverflow(borrow)
            result[index] = second.partialValue
            borrow = first.overflow || second.overflow ? 1 : 0
        }
        precondition(borrow == 0)
        return Self(words: result)
    }

    internal func shiftedRightOneBit() -> Self {
        guard !words.isEmpty else { return .zero }
        var result = words
        var carry: UInt32 = 0

        for index in result.indices.reversed() {
            let nextCarry = result[index] & 1
            result[index] = (result[index] >> 1) | (carry << 31)
            carry = nextCarry
        }
        return Self(words: result)
    }

    internal func multipliedModulo(_ other: Self, modulus: Self) -> Self {
        precondition(!modulus.isZero)
        precondition(self < modulus)
        precondition(other < modulus)

        var result = Self.zero
        var addend = self
        for bitIndex in 0 ..< other.bitCount {
            if other.isBitSet(at: bitIndex) {
                result = Self.addingModulo(result, addend, modulus: modulus)
            }
            addend = Self.addingModulo(addend, addend, modulus: modulus)
        }
        return result
    }

    internal func inverseModulo(_ modulus: Self) -> Self? {
        guard !isZero, self < modulus, !modulus.isZero, !modulus.isEven else {
            return nil
        }

        var leftValue = self
        var rightValue = modulus
        var leftCoefficient = Self.one
        var rightCoefficient = Self.zero

        while !leftValue.isOne && !rightValue.isOne {
            guard !leftValue.isZero, !rightValue.isZero else { return nil }

            while !leftValue.isZero && leftValue.isEven {
                leftValue.shiftRightOneBitInPlace()
                leftCoefficient.halveModuloInPlace(modulus)
            }
            while !rightValue.isZero && rightValue.isEven {
                rightValue.shiftRightOneBitInPlace()
                rightCoefficient.halveModuloInPlace(modulus)
            }

            guard !leftValue.isZero, !rightValue.isZero else { return nil }
            if leftValue >= rightValue {
                leftValue.subtractInPlace(rightValue)
                leftCoefficient.subtractModuloInPlace(rightCoefficient, modulus: modulus)
            } else {
                rightValue.subtractInPlace(leftValue)
                rightCoefficient.subtractModuloInPlace(leftCoefficient, modulus: modulus)
            }
        }

        return leftValue.isOne ? leftCoefficient : rightCoefficient
    }

    private var bigEndianRepresentation: Data {
        guard let mostSignificantWord = words.last else { return Data() }
        var result = Data()
        result.reserveCapacity(words.count * 4)

        for index in words.indices.reversed() {
            let word = words[index]
            let bytes = [
                UInt8(truncatingIfNeeded: word >> 24),
                UInt8(truncatingIfNeeded: word >> 16),
                UInt8(truncatingIfNeeded: word >> 8),
                UInt8(truncatingIfNeeded: word)
            ]
            if index == words.count - 1 {
                let leadingByteCount = mostSignificantWord.leadingZeroBitCount / 8
                result.append(contentsOf: bytes.dropFirst(leadingByteCount))
            } else {
                result.append(contentsOf: bytes)
            }
        }
        return result
    }

    private static func addingModulo(
        _ left: Self,
        _ right: Self,
        modulus: Self
    ) -> Self {
        let sum = left.adding(right)
        return sum >= modulus ? sum.subtracting(modulus) : sum
    }

    private mutating func addInPlace(_ other: Self) {
        let resultCount = max(words.count, other.words.count)
        if words.count < resultCount {
            words.append(contentsOf: repeatElement(0, count: resultCount - words.count))
        }

        var carry: UInt64 = 0
        for index in 0 ..< resultCount {
            let right = index < other.words.count ? UInt64(other.words[index]) : 0
            let sum = UInt64(words[index]) + right + carry
            words[index] = UInt32(truncatingIfNeeded: sum)
            carry = sum >> 32
        }
        if carry != 0 {
            words.append(UInt32(carry))
        }
    }

    private mutating func subtractInPlace(_ other: Self) {
        precondition(self >= other)
        var borrow: UInt32 = 0
        for index in words.indices {
            let right = index < other.words.count ? other.words[index] : 0
            let first = words[index].subtractingReportingOverflow(right)
            let second = first.partialValue.subtractingReportingOverflow(borrow)
            words[index] = second.partialValue
            borrow = first.overflow || second.overflow ? 1 : 0
        }
        precondition(borrow == 0)
        while words.last == 0 {
            words.removeLast()
        }
    }

    private mutating func shiftRightOneBitInPlace() {
        var carry: UInt32 = 0
        for index in words.indices.reversed() {
            let nextCarry = words[index] & 1
            words[index] = (words[index] >> 1) | (carry << 31)
            carry = nextCarry
        }
        while words.last == 0 {
            words.removeLast()
        }
    }

    // Inverse coefficients stay in [0, modulus); only the request-local
    // value buffers change, while the binary GCD control flow stays intact.
    private mutating func subtractModuloInPlace(_ other: Self, modulus: Self) {
        if self < other {
            addInPlace(modulus)
        }
        subtractInPlace(other)
    }

    private mutating func halveModuloInPlace(_ modulus: Self) {
        if !isEven {
            addInPlace(modulus)
        }
        shiftRightOneBitInPlace()
    }

    private init(words: [UInt32]) {
        var normalizedWords = words
        while normalizedWords.last == 0 {
            normalizedWords.removeLast()
        }
        self.words = normalizedWords
    }
}
