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

    static func convertBatchToAffine(_ points: [JacobianPointModel]) -> [AffinePointModel?] {
        let temporaryAllocationThreshold = 64
        var pointIndices: [Int] = .init()
        pointIndices.reserveCapacity(points.count)
        for index in points.indices where !points[index].isInfinity {
            pointIndices.append(index)
        }

        var results = Array<AffinePointModel?>(repeating: nil, count: points.count)
        guard !pointIndices.isEmpty else { return results }

        if pointIndices.count <= temporaryAllocationThreshold {
            // SAFETY: prefixProducts has pointIndices.count elements. The
            // forward pass initializes every position before the reverse pass
            // reads it, and the temporary pointer cannot escape this closure.
            return withUnsafeTemporaryAllocation(of: FieldElementModel.self, capacity: pointIndices.count) { prefixProducts in
                var productAccumulator = FieldElementModel.one
                for (position, index) in pointIndices.enumerated() {
                    productAccumulator = productAccumulator.mul(points[index].Z)
                    prefixProducts[position] = productAccumulator
                }

                var inverseAccumulator = productAccumulator.invert()

                for position in pointIndices.indices.reversed() {
                    let pointIndex = pointIndices[position]
                    let zCoordinate = points[pointIndex].Z
                    let prefixProduct = position == pointIndices.startIndex ? FieldElementModel.one : prefixProducts[position - 1]

                    let zCoordinateInverse = inverseAccumulator.mul(prefixProduct)
                    inverseAccumulator = inverseAccumulator.mul(zCoordinate)

                    let zCoordinateInverseSquared = zCoordinateInverse.square()
                    let x = points[pointIndex].X.mul(zCoordinateInverseSquared)
                    let y = points[pointIndex].Y.mul(zCoordinateInverseSquared.mul(zCoordinateInverse))
                    results[pointIndex] = AffinePointModel(x: x, y: y)
                }

                return results
            }
        }

        var prefixProducts: [FieldElementModel] = .init()
        prefixProducts.reserveCapacity(pointIndices.count)
        var productAccumulator = FieldElementModel.one
        for index in pointIndices {
            productAccumulator = productAccumulator.mul(points[index].Z)
            prefixProducts.append(productAccumulator)
        }

        var inverseAccumulator = productAccumulator.invert()

        for position in pointIndices.indices.reversed() {
            let pointIndex = pointIndices[position]
            let zCoordinate = points[pointIndex].Z
            let prefixProduct = position == pointIndices.startIndex ? FieldElementModel.one : prefixProducts[position - 1]

            let zCoordinateInverse = inverseAccumulator.mul(prefixProduct)
            inverseAccumulator = inverseAccumulator.mul(zCoordinate)

            let zCoordinateInverseSquared = zCoordinateInverse.square()
            let x = points[pointIndex].X.mul(zCoordinateInverseSquared)
            let y = points[pointIndex].Y.mul(zCoordinateInverseSquared.mul(zCoordinateInverse))
            results[pointIndex] = AffinePointModel(x: x, y: y)
        }

        return results
    }
}
