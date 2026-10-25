// JacobianPointModel~BatchConversion.swift

import Foundation

extension JacobianPointModel {
    static func convertNonInfinityBatchToAffine(
        _ points: [JacobianPointModel]
    ) -> [AffinePointModel] {
        let temporaryAllocationThreshold = 64
        guard !points.isEmpty else { return .init() }
        assert(points.allSatisfy { !$0.isInfinity })

        if points.count <= temporaryAllocationThreshold {
            // SAFETY: Both buffers have points.count elements. The forward pass
            // initializes every prefix product before the reverse pass reads it,
            // and the reverse pass assigns every result index exactly once before
            // initializedCount exposes the array. Neither buffer escapes its
            // allocation closure.
            return Array(unsafeUninitializedCapacity: points.count) { buffer, initializedCount in
                withUnsafeTemporaryAllocation(
                    of: FieldElementModel.self,
                    capacity: points.count
                ) { prefixProducts in
                    var productAccumulator = FieldElementModel.one
                    for (index, point) in points.enumerated() {
                        productAccumulator = productAccumulator.mul(point.Z)
                        prefixProducts[index] = productAccumulator
                    }

                    var inverseAccumulator = productAccumulator.invert()

                    for index in points.indices.reversed() {
                        let point = points[index]
                        let prefixProduct = index == points.startIndex
                            ? FieldElementModel.one
                            : prefixProducts[index - 1]

                        let zCoordinateInverse = inverseAccumulator.mul(prefixProduct)
                        inverseAccumulator = inverseAccumulator.mul(point.Z)

                        let zCoordinateInverseSquared = zCoordinateInverse.square()
                        buffer[index] = AffinePointModel(
                            x: point.X.mul(zCoordinateInverseSquared),
                            y: point.Y.mul(zCoordinateInverseSquared.mul(zCoordinateInverse))
                        )
                    }
                }
                initializedCount = points.count
            }
        }

        var prefixProducts: [FieldElementModel] = .init()
        prefixProducts.reserveCapacity(points.count)
        var productAccumulator = FieldElementModel.one
        for point in points {
            productAccumulator = productAccumulator.mul(point.Z)
            prefixProducts.append(productAccumulator)
        }

        var inverseAccumulator = productAccumulator.invert()
        // SAFETY: The result buffer has points.count elements, and the reverse
        // loop initializes each valid index exactly once before initializedCount
        // exposes the array. The pointer remains scoped to this closure.
        return Array(unsafeUninitializedCapacity: points.count) { buffer, initializedCount in
            for index in points.indices.reversed() {
                let point = points[index]
                let prefixProduct = index == points.startIndex
                    ? FieldElementModel.one
                    : prefixProducts[index - 1]

                let zCoordinateInverse = inverseAccumulator.mul(prefixProduct)
                inverseAccumulator = inverseAccumulator.mul(point.Z)

                let zCoordinateInverseSquared = zCoordinateInverse.square()
                buffer[index] = AffinePointModel(
                    x: point.X.mul(zCoordinateInverseSquared),
                    y: point.Y.mul(zCoordinateInverseSquared.mul(zCoordinateInverse))
                )
            }
            initializedCount = points.count
        }
    }

}
