// BatchJacobianPointBufferModel.swift

import Foundation

package struct BatchJacobianPointBufferModel: Sendable {
    let points: [JacobianPointModel]

    init(points: [JacobianPointModel]) {
        self.points = points
    }
}
