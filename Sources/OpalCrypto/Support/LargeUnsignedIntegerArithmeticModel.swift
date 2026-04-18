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
    
    internal func shiftLeft(byBytes byteShift: Int) -> LargeUnsignedIntegerArithmeticModel {
        guard byteShift > 0 else { return self }
        guard !words.isEmpty else { return .zero }
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
    
    internal func shiftRight(byBytes byteShift: Int) -> LargeUnsignedIntegerArithmeticModel {
        guard byteShift > 0 else { return self }
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
    
    internal mutating func add(_ addend: UInt64) {
        let addendWords = [
            UInt32(addend & 0xffff_ffff),
            UInt32(addend >> 32)
        ]
        var carry: UInt64 = 0

        for (index, addendWord) in addendWords.enumerated() {
            guard addendWord > 0 || carry > 0 else {
                continue
            }
            while index >= words.count {
                words.append(0)
            }
            let sum = UInt64(words[index]) + UInt64(addendWord) + carry
            words[index] = UInt32(sum & 0xffff_ffff)
            carry = sum >> 32
        }

        var carryIndex = addendWords.count
        while carry > 0 {
            while carryIndex >= words.count {
                words.append(0)
            }
            let sum = UInt64(words[carryIndex]) + carry
            words[carryIndex] = UInt32(sum & 0xffff_ffff)
            carry = sum >> 32
            carryIndex += 1
        }
    }
    
    internal mutating func multiply(by multiplier: UInt64) {
        guard !words.isEmpty, multiplier > 1 else {
            if multiplier == 0 {
                words = .init()
            }
            return
        }
        
        guard multiplier > UInt64(UInt32.max) else {
            multiply(byWord: UInt32(multiplier))
            return
        }

        let multiplicandWords = words
        let multiplierWords = [
            UInt32(multiplier & 0xffff_ffff),
            UInt32(multiplier >> 32)
        ]
        var productWords = Array(
            repeating: UInt32(0),
            count: multiplicandWords.count + multiplierWords.count
        )
        
        // Split larger multipliers into base-2^32 limbs so each partial product fits in UInt64.
        for (multiplierIndex, multiplierWord) in multiplierWords.enumerated() where multiplierWord > 0 {
            var carry: UInt64 = 0
            for multiplicandIndex in multiplicandWords.indices {
                let productIndex = multiplicandIndex + multiplierIndex
                let partialProduct = UInt64(multiplicandWords[multiplicandIndex]) * UInt64(multiplierWord)
                let sum = UInt64(productWords[productIndex]) + partialProduct + carry
                productWords[productIndex] = UInt32(sum & 0xffff_ffff)
                carry = sum >> 32
            }
            
            var carryIndex = multiplicandWords.count + multiplierIndex
            while carry > 0 {
                if carryIndex == productWords.count {
                    productWords.append(0)
                }
                let sum = UInt64(productWords[carryIndex]) + carry
                productWords[carryIndex] = UInt32(sum & 0xffff_ffff)
                carry = sum >> 32
                carryIndex += 1
            }
        }
        
        self = LargeUnsignedIntegerArithmeticModel(words: productWords)
    }
    
    internal mutating func divide(by divisor: UInt64) -> UInt64 {
        guard divisor > 0, !words.isEmpty else { return 0 }
        var remainder: UInt64 = 0
        var quotientWords = Array(repeating: UInt32(0), count: words.count)
        for index in words.indices.reversed() {
            // Each base-2^32 long-division step can exceed UInt64 when the prior
            // remainder already uses more than 32 bits, so split the 96-bit
            // intermediate across a full-width dividend instead of truncating it.
            let high = remainder >> 32
            let low = ((remainder & 0xffff_ffff) << 32) | UInt64(words[index])
            let division = divisor.dividingFullWidth((high: high, low: low))
            let quotient = division.quotient
            remainder = division.remainder
            quotientWords[index] = UInt32(quotient)
        }
        self = LargeUnsignedIntegerArithmeticModel(words: quotientWords)
        return remainder
    }
    
    private init(words: [UInt32]) {
        self.words = words
        normalize()
    }
    
    private mutating func multiply(byWord multiplier: UInt32) {
        var carry: UInt64 = 0
        let multiplierValue = UInt64(multiplier)
        for index in words.indices {
            let product = UInt64(words[index]) * multiplierValue + carry
            words[index] = UInt32(product & 0xffff_ffff)
            carry = product >> 32
        }
        if carry > 0 {
            words.append(UInt32(carry))
        }
    }
    
    private mutating func normalize() {
        while let last = words.last, last == 0 {
            words.removeLast()
        }
    }
}
