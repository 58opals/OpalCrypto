// StandardsForEfficientCryptography256k1CurveModel.Operation+CompressedPublicKeyBatchDerivationExecutionMode.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    enum CompressedPublicKeyBatchDerivationExecutionMode: Sendable {
        case automatic
        case serial
        case parallel
    }
}
