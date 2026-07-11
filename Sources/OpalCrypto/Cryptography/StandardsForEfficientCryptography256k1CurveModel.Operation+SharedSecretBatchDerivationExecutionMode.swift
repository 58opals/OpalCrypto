// StandardsForEfficientCryptography256k1CurveModel.Operation+SharedSecretBatchDerivationExecutionMode.swift

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    enum SharedSecretBatchDerivationExecutionMode: Sendable {
        case automatic
        case serial
        case parallel
    }
}
