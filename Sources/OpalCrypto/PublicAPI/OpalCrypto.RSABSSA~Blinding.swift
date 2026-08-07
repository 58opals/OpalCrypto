// OpalCrypto.RSABSSA~Blinding.swift

import Foundation

extension OpalCrypto.RSABSSA {
    /// Randomizes, PSS-encodes, and blinds `message` for `verificationKey`.
    ///
    /// Randomized preparation, the PSS salt, and the blinding factor all use
    /// the operating system's cryptographically secure random generator.
    public static func makeBlindRequest(
        message: Data,
        using verificationKey: VerificationKey
    ) throws -> BlindRequest {
        try BlindRequest(
            material: RSABSSAModel.makeBlindRequest(
                message: message,
                verificationKey: verificationKey.model
            )
        )
    }
}
