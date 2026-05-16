// BatchJacobianPointBuffer.swift

import Foundation

package struct BatchJacobianPointBuffer: Sendable {
    let points: [JacobianPointModel]

    init(points: [JacobianPointModel]) {
        self.points = points
    }
}
