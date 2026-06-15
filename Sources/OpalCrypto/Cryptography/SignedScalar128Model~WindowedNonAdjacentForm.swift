// SignedScalar128Model~WindowedNonAdjacentForm.swift

import Foundation

extension SignedScalar128Model {
    struct WindowedNonAdjacentForm: Sendable {
        private var digits: InlineArray<130, Int8>
        private(set) var count: Int

        init() {
            digits = .init(repeating: 0)
            count = 0
        }

        subscript(index: Int) -> Int8 {
            precondition(index >= 0 && index < count, "Windowed non-adjacent form digit index out of range.")
            return digits[index]
        }

        mutating func append(_ digit: Int8) {
            precondition(count < 130, "Windowed non-adjacent form digit capacity exceeded.")
            digits[count] = digit
            count += 1
        }

        var values: [Int8] {
            var result: [Int8] = .init()
            result.reserveCapacity(count)
            for index in 0..<count {
                result.append(digits[index])
            }
            return result
        }
    }

    static func makeWindowedNonAdjacentForm(
        _ scalar: SignedScalar128Model,
        width: Int
    ) -> WindowedNonAdjacentForm {
        precondition(width >= 2 && width <= 8, "Unsupported window width for windowed non-adjacent form.")
        var digits = WindowedNonAdjacentForm()
        guard !scalar.isZero else {
            digits.append(0)
            return digits
        }
        
        let windowMask = UInt64((1 << width) - 1)
        let windowHalf = Int64(1 << (width - 1))
        let windowFull = Int64(1 << width)
        
        var magnitude = scalar.magnitude
        
        while !magnitude.isZero {
            var digit: Int64 = 0
            if (magnitude.limbs[0] & 1) == 1 {
                let lowBits = Int64(magnitude.limbs[0] & windowMask)
                digit = lowBits
                if digit > windowHalf {
                    digit -= windowFull
                }
                if digit < 0 {
                    magnitude = magnitude.addWord(UInt64(-digit))
                } else {
                    magnitude = magnitude.subtractWord(UInt64(digit))
                }
            }
            
            digits.append(scalar.isNegative ? Int8(-digit) : Int8(digit))
            magnitude = magnitude.shiftRightOneBit()
        }
        
        return digits
    }
}
