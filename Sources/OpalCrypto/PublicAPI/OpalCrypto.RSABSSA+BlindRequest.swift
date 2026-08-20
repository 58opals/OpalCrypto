// OpalCrypto.RSABSSA+BlindRequest.swift

import Foundation

extension OpalCrypto.RSABSSA {
    /// Client state for one randomized blind-signature request.
    ///
    /// Retain this value until finalization. Only ``blindedMessage`` is sent to
    /// the signer; the hidden inverse must remain local to the requesting client.
    public struct BlindRequest: Sendable {
        internal let material: RSABSSAModel.BlindRequestMaterial

        /// The request value sent to the blind signer.
        public let blindedMessage: BlindedMessage

        /// The randomized prefix that accompanies the finalized signature.
        public let messageRandomizer: MessageRandomizer

        /// Sensitive one-request state for exact encrypted recovery.
        ///
        /// Store this value only inside application-owned authenticated encryption. Reuse for
        /// another message, key, attempt, or successful finalization is outside this contract.
        public let recoveryState: RecoveryState

        /// Validates and unblinds the signer's response, then verifies the
        /// resulting RSA-PSS signature before returning it.
        public func finalize(
            _ blindSignature: BlindSignature,
            using verificationKey: VerificationKey
        ) throws -> Signature {
            try Signature(
                rawRepresentation: RSABSSAModel.finalize(
                    blindSignature: blindSignature.rawRepresentation,
                    request: material,
                    verificationKey: verificationKey.model
                )
            )
        }

        internal init(material: RSABSSAModel.BlindRequestMaterial) throws {
            self.material = material
            self.blindedMessage = try BlindedMessage(
                rawRepresentation: material.blindedMessage
            )
            self.messageRandomizer = try MessageRandomizer(
                rawRepresentation: material.messageRandomizer
            )
            self.recoveryState = RecoveryState(material: material)
        }
    }
}
