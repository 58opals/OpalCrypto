// ScalarConversionModel.swift

import Foundation

enum ScalarConversionModel {
    static func makeReducedScalar(from data32: Data) throws -> ScalarModel {
        let parsed = try Unsigned256BitIntegerModel(data32: data32)
        var reduced = parsed
        if reduced.compare(to: StandardsForEfficientCryptography256k1CurveModel.Constant.n) != .orderedAscending {
            reduced = reduced.subtract(StandardsForEfficientCryptography256k1CurveModel.Constant.n).difference
        }
        return ScalarModel(unchecked: reduced)
    }

    static func makeScalarFromFieldElement(_ fieldElement: FieldElementModel) throws -> ScalarModel {
        let parsed = try Unsigned256BitIntegerModel(data32: fieldElement.data32)
        var reduced = parsed
        if reduced.compare(to: StandardsForEfficientCryptography256k1CurveModel.Constant.n) != .orderedAscending {
            reduced = reduced.subtract(StandardsForEfficientCryptography256k1CurveModel.Constant.n).difference
        }
        return ScalarModel(unchecked: reduced)
    }
    
    static func makeReducedScalarFromDigest(_ digest32: Data) throws -> ScalarModel {
        try makeReducedScalar(from: digest32)
    }
    
    static func makeReducedDataFromDigest(_ digest32: Data) throws -> Data {
        let reducedScalar = try makeReducedScalarFromDigest(digest32)
        return reducedScalar.data32
    }
}
