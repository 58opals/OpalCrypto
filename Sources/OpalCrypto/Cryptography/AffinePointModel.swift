// AffinePointModel.swift

import Foundation

struct AffinePointModel: Sendable, Equatable {
    let x: FieldElementModel
    let y: FieldElementModel
    
    var isOnCurve: Bool {
        let left = y.square()
        let right = x.square().mul(x).add(.seven)
        return left == right
    }

    func appendCompressed33Bytes(to data: inout Data) {
        data.append(y.isOdd ? 0x03 : 0x02)
        data.appendUnsigned256BitIntegerBigEndian(x.value)
    }

    func appendUncompressed65Bytes(to data: inout Data) {
        data.append(0x04)
        data.appendUnsigned256BitIntegerBigEndian(x.value)
        data.appendUnsigned256BitIntegerBigEndian(y.value)
    }
    
    func encodeCompressed33() -> Data {
        var output = Data()
        output.reserveCapacity(33)
        appendCompressed33Bytes(to: &output)
        return output
    }
    
    func encodeUncompressed65() -> Data {
        var output = Data()
        output.reserveCapacity(65)
        appendUncompressed65Bytes(to: &output)
        return output
    }
    
    func negate() -> AffinePointModel {
        AffinePointModel(x: x, y: y.negate())
    }
    
    func applyEndomorphism() -> AffinePointModel {
        let beta = FieldElementModel(unchecked: StandardsForEfficientCryptography256k1CurveModel.Constant.endomorphismBeta)
        return AffinePointModel(x: beta.mul(x), y: y)
    }
}
