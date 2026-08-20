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

    /// Restores the exact blind request from app-authenticated sensitive state.
    ///
    /// This performs the same bounded PSS encoding and blinding validation as initial
    /// construction. The state is bound to the byte-exact message and verification key.
    public static func restoreBlindRequest(
        message: Data,
        using verificationKey: VerificationKey,
        from recoveryState: BlindRequest.RecoveryState
    ) throws -> BlindRequest {
        guard recoveryState.verificationKeyIdentifier
                == verificationKey.keyIdentifier else {
            throw Error.verificationKeyMismatch
        }
        guard recoveryState.messageDigest
                == OpalCrypto.Hashing.sha256(message) else {
            throw Error.blindRequestMessageMismatch
        }
        return try BlindRequest(
            material: RSABSSAModel.makeBlindRequest(
                message: message,
                verificationKey: verificationKey.model,
                messageRandomizer: recoveryState.messageRandomizer,
                salt: recoveryState.salt,
                blindingFactor: recoveryState.blindingFactor
            )
        )
    }
}
