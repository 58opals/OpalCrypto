// OpalCryptoBenchmarks.MetalValidation~FieldOperations.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks.MetalValidation {
    static func validateFieldOperations() throws -> Int {
        let boundaryValues = try [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
        ].map(decodeHex)

        var validationCases: [MetalFieldValidationBenchmarkCase] = .init()
        validationCases.reserveCapacity(10_000 + boundaryValues.count * boundaryValues.count)
        for left in boundaryValues {
            for right in boundaryValues {
                validationCases.append(
                    try PerformanceBenchmarkOperations.makeMetalFieldValidationCase(
                        leftData32: left,
                        rightData32: right
                    )
                )
            }
        }

        var generator = DeterministicGenerator(state: 0x4f70_616c_4d65_7461)
        var upperHalfGeneratedOperandCount = 0
        for _ in 0..<10_000 {
            let left = generator.nextCanonicalFieldBytes()
            let right = generator.nextCanonicalFieldBytes()
            upperHalfGeneratedOperandCount += left[0] & 0x80 == 0 ? 0 : 1
            upperHalfGeneratedOperandCount += right[0] & 0x80 == 0 ? 0 : 1
            validationCases.append(
                try PerformanceBenchmarkOperations.makeMetalFieldValidationCase(
                    leftData32: left,
                    rightData32: right
                )
            )
        }
        guard upperHalfGeneratedOperandCount > 0 else {
            throw Error.unexpectedResult(
                "generated field cases did not cover the upper half of the field"
            )
        }

        let checksum = try OpalCryptoBenchmarks.MetalSchnorrVerificationCore
            .validateFieldOperations(
            validationCases
        )
        print("Metal field differential cases: \(validationCases.count)")
        print(
            "Metal upper-half generated field operands: "
                + "\(upperHalfGeneratedOperandCount)"
        )
        return checksum
    }

}
