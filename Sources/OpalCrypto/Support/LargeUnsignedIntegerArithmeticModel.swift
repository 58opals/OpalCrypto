// LargeUnsignedIntegerArithmeticModel.swift

import Foundation

internal struct LargeUnsignedIntegerArithmeticModel: Comparable, Sendable {
    private var words: [UInt32]
    
    internal static let zero = LargeUnsignedIntegerArithmeticModel(words: .init())
    
    internal init(_ value: UInt64) {
        if value == 0 {
            self.words = .init()
        } else {
            let lower = UInt32(value & 0xffff_ffff)
            let upper = UInt32(value >> 32)
            self.words = upper == 0 ? [lower] : [lower, upper]
        }
    }
    
    internal init(_ data: Data) {
        guard !data.isEmpty else {
            self.words = .init()
            return
        }
        var values: [UInt32] = .init()
        values.reserveCapacity((data.count + 3) / 4)
        var index = data.count
        while index > 0 {
            let start = Swift.max(0, index - 4)
            let chunk = data[start..<index]
            var value: UInt32 = 0
            for byte in chunk {
                value = (value << 8) | UInt32(byte)
            }
            values.append(value)
            index = start
        }
        self.words = values
        normalize()
    }
    
    internal var isZero: Bool {
        words.isEmpty
    }
    
    internal func serialize() -> Data {
        guard !words.isEmpty else { return Data() }
        let mostSignificantWord = words[words.count - 1]
        let mostSignificantByteCount: Int
        switch mostSignificantWord {
        case 0x0000_0000...0x0000_00ff:
            mostSignificantByteCount = 1
        case 0x0000_0100...0x0000_ffff:
            mostSignificantByteCount = 2
        case 0x0001_0000...0x00ff_ffff:
            mostSignificantByteCount = 3
        default:
            mostSignificantByteCount = 4
        }

        var data = Data()
        data.reserveCapacity((words.count - 1) * 4 + mostSignificantByteCount)
        for index in words.indices.reversed() {
            let word = words[index]
            if index == words.count - 1 {
                if mostSignificantByteCount >= 4 {
                    data.append(UInt8((word >> 24) & 0xff))
                }
                if mostSignificantByteCount >= 3 {
                    data.append(UInt8((word >> 16) & 0xff))
                }
                if mostSignificantByteCount >= 2 {
                    data.append(UInt8((word >> 8) & 0xff))
                }
                data.append(UInt8(word & 0xff))
            } else {
                data.append(UInt8((word >> 24) & 0xff))
                data.append(UInt8((word >> 16) & 0xff))
                data.append(UInt8((word >> 8) & 0xff))
                data.append(UInt8(word & 0xff))
            }
        }
        return data
    }
    
    internal func shiftLeft(by bits: Int) -> LargeUnsignedIntegerArithmeticModel {
        guard bits > 0 else { return self }
        precondition(bits % 8 == 0, "Shift must be a multiple of 8.")
        guard !words.isEmpty else { return .zero }

        let byteShift = bits / 8
        let wordShift = byteShift / 4
        let intraWordByteShift = byteShift % 4
        let intraWordBitShift = intraWordByteShift * 8
        var shiftedWords = Array(
            repeating: UInt32(0),
            count: words.count + wordShift + (intraWordBitShift == 0 ? 0 : 1)
        )

        for index in words.indices {
            let destinationIndex = index + wordShift
            if intraWordBitShift == 0 {
                shiftedWords[destinationIndex] = words[index]
            } else {
                let value = UInt64(words[index]) << intraWordBitShift
                shiftedWords[destinationIndex] |= UInt32(value & 0xffff_ffff)
                shiftedWords[destinationIndex + 1] |= UInt32(value >> 32)
            }
        }

        return LargeUnsignedIntegerArithmeticModel(words: shiftedWords)
    }
    
    internal func shiftRight(by bits: Int) -> LargeUnsignedIntegerArithmeticModel {
        guard bits > 0 else { return self }
        precondition(bits % 8 == 0, "Shift must be a multiple of 8.")
        let byteShift = bits / 8
        let wordShift = byteShift / 4
        let intraWordByteShift = byteShift % 4
        let intraWordBitShift = intraWordByteShift * 8

        guard wordShift < words.count else { return .zero }
        if intraWordBitShift == 0 {
            return LargeUnsignedIntegerArithmeticModel(words: Array(words[wordShift...]))
        }

        var shiftedWords: [UInt32] = .init()
        shiftedWords.reserveCapacity(words.count - wordShift)
        let carryBitShift = 32 - intraWordBitShift

        for index in wordShift..<words.count {
            var shiftedWord = words[index] >> intraWordBitShift
            if index + 1 < words.count {
                shiftedWord |= words[index + 1] << carryBitShift
            }
            shiftedWords.append(shiftedWord)
        }

        return LargeUnsignedIntegerArithmeticModel(words: shiftedWords)
    }
    
    internal static func < (lhs: LargeUnsignedIntegerArithmeticModel, rhs: LargeUnsignedIntegerArithmeticModel) -> Bool {
        if lhs.words.count != rhs.words.count {
            return lhs.words.count < rhs.words.count
        }
        for (leftWord, rightWord) in zip(lhs.words.reversed(), rhs.words.reversed()) {
            if leftWord != rightWord {
                return leftWord < rightWord
            }
        }
        return false
    }
    
    internal mutating func add(_ addend: Int) {
        precondition(addend >= 0, "Addend must be non-negative.")
        var carry = UInt64(addend)
        var index = 0
        while carry > 0 {
            if index == words.count {
                words.append(0)
            }
            let sum = UInt64(words[index]) + carry
            words[index] = UInt32(sum & 0xffff_ffff)
            carry = sum >> 32
            index += 1
        }
    }
    
    internal mutating func multiply(by multiplier: Int) {
        precondition(multiplier >= 0, "Multiplier must be non-negative.")
        guard !words.isEmpty, multiplier > 1 else {
            if multiplier == 0 {
                words = .init()
            }
            return
        }
        var carry: UInt64 = 0
        for index in words.indices {
            let product = UInt64(words[index]) * UInt64(multiplier) + carry
            words[index] = UInt32(product & 0xffff_ffff)
            carry = product >> 32
        }
        if carry > 0 {
            words.append(UInt32(carry))
        }
    }
    
    internal mutating func divide(by divisor: Int) -> Int {
        precondition(divisor > 0, "Divisor must be positive.")
        guard !words.isEmpty else { return 0 }
        var remainder: UInt64 = 0
        var quotientWords = Array(repeating: UInt32(0), count: words.count)
        for index in words.indices.reversed() {
            let value = (remainder << 32) + UInt64(words[index])
            let quotient = value / UInt64(divisor)
            remainder = value % UInt64(divisor)
            quotientWords[index] = UInt32(quotient)
        }
        self = LargeUnsignedIntegerArithmeticModel(words: quotientWords)
        return Int(remainder)
    }
    
    private init(words: [UInt32]) {
        self.words = words
        normalize()
    }
    
    private mutating func normalize() {
        while let last = words.last, last == 0 {
            words.removeLast()
        }
    }
}
