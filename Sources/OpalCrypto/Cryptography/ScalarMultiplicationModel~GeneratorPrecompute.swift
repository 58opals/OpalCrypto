// ScalarMultiplicationModel~GeneratorPrecompute.swift

import Foundation

extension ScalarMultiplicationModel {
    @usableFromInline static let generatorWindowedNonAdjacentFormWidth = 5
    @usableFromInline static let generatorWindowedNonAdjacentFormOddMultipleCount = 8
    @usableFromInline static let verificationKeyWindowedNonAdjacentFormWidth = 5
    @usableFromInline static let verificationKeyWindowedNonAdjacentFormOddMultipleCount = 8
    
    @usableFromInline static let generatorOddMultiplesAffine: InlineArray<8, AffinePointModel> = {
        makeGeneratorOddMultiplesAffineTable(for: generator)
    }()
    
    @usableFromInline static let generatorEndomorphismOddMultiplesAffine: InlineArray<8, AffinePointModel> = {
        makeGeneratorOddMultiplesAffineTable(for: generator.applyEndomorphism())
    }()
    
    static func makeGeneratorOddMultiplesAffineTable(
        for basePoint: AffinePointModel
    ) -> InlineArray<8, AffinePointModel> {
        makeOddMultiplesAffineTable(
            for: basePoint,
            oddMultipleCount: generatorWindowedNonAdjacentFormOddMultipleCount
        )
    }

    static func makeVerificationKeyOddMultiplesAffineTable(
        for basePoint: AffinePointModel
    ) -> InlineArray<8, AffinePointModel> {
        makeOddMultiplesAffineTable(
            for: basePoint,
            oddMultipleCount: verificationKeyWindowedNonAdjacentFormOddMultipleCount
        )
    }

    private static func makeOddMultiplesAffineTable(
        for basePoint: AffinePointModel,
        oddMultipleCount: Int
    ) -> InlineArray<8, AffinePointModel> {
        var jacobianPoints: [JacobianPointModel] = .init()
        jacobianPoints.reserveCapacity(oddMultipleCount)
        
        let baseJacobian = JacobianPointModel(affine: basePoint)
        let doubleBase = baseJacobian.double()
        var accumulator = baseJacobian
        for _ in 0..<oddMultipleCount {
            jacobianPoints.append(accumulator)
            accumulator = accumulator.add(doubleBase)
        }
        
        let affinePoints = JacobianPointModel.convertNonInfinityBatchToAffine(
            jacobianPoints
        )
        var affineTable: InlineArray<8, AffinePointModel> = .init(repeating: basePoint)
        for index in 0..<oddMultipleCount {
            affineTable[index] = affinePoints[index]
        }
        return affineTable
    }
}
