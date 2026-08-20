// RSABSSAModel.swift

import Foundation

internal enum RSABSSAModel {
    internal struct BlindRequestMaterial: Sendable {
        internal let preparedMessage: Data
        internal let messageDigest: Data
        internal let messageRandomizer: Data
        internal let salt: Data
        internal let blindingFactor: Data
        internal let blindedMessage: Data
        internal let blindInverse: Data
        internal let verificationKeyIdentifier: Data
    }
}
