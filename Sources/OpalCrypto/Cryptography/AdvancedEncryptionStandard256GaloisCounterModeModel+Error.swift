// AdvancedEncryptionStandard256GaloisCounterModeModel+Error.swift

extension AdvancedEncryptionStandard256GaloisCounterModeModel {
    internal enum Error: Swift.Error, Equatable {
        case invalidSealedBox
        case sealingFailed
        case authenticationFailed
    }
}
