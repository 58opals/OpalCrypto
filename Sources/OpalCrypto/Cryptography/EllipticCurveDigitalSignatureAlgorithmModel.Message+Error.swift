// EllipticCurveDigitalSignatureAlgorithmModel.Message+Error.swift

import Foundation
import CryptoKit

extension EllipticCurveDigitalSignatureAlgorithmModel.Message {
    internal enum Error: Swift.Error {
        case hashCountMustBeGreaterThanZero
        case invalidDigestByteCount(expected: Int, actual: Int)
    }
}
