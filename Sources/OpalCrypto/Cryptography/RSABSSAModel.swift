// RSABSSAModel.swift

import Foundation

internal enum RSABSSAModel {
    internal struct BlindRequestMaterial: Sendable {
        internal let preparedMessage: Data
        internal let messageRandomizer: Data
        internal let blindedMessage: Data
        internal let blindInverse: Data
        internal let verificationKeyIdentifier: Data
    }
}
