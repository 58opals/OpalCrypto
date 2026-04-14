// EllipticCurveDigitalSignatureAlgorithmModel.Message+Representation.swift

import Foundation
import CryptoKit

extension EllipticCurveDigitalSignatureAlgorithmModel.Message {
    enum Representation {
        case payload(data: Data, hashRounds: UInt8)
        case digest(digest: CryptoKit.SHA256.Digest, hashRounds: UInt8)
    }
}
