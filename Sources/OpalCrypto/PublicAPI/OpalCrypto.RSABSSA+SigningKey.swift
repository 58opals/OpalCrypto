// OpalCrypto.RSABSSA+SigningKey.swift

extension OpalCrypto.RSABSSA {
    /// An opaque RSA-2048 capability for one RSABSSA attempt.
    ///
    /// Generate a fresh value for every attempt and never reuse it for another
    /// protocol or RSABSSA parameter set.
    public struct SigningKey: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
        internal let model: RSABSSASigningKeyModel

        /// The verification key distributed in the attempt manifest.
        public let verificationKey: VerificationKey

        /// Generates a fresh, nonpersistent RSA-2048 signing key.
        public static func generate() throws -> Self {
            Self(model: try RSABSSASigningKeyModel.generate())
        }

        /// Performs RFC 9474 BlindSign and verifies the raw RSA result as a
        /// fault-attack safeguard before returning it.
        public func blindSign(
            _ blindedMessage: BlindedMessage
        ) throws -> BlindSignature {
            try BlindSignature(
                rawRepresentation: RSABSSAModel.blindSign(
                    blindedMessage: blindedMessage.rawRepresentation,
                    signingKey: model
                )
            )
        }

        /// A redacted description that never includes private-key material.
        public var description: String {
            "OpalCrypto.RSABSSA.SigningKey(redacted, variant: \(Variant.sha384PSSRandomized.rawValue))"
        }

        /// A redacted debug description that never includes private-key material.
        public var debugDescription: String { description }

        internal init(model: RSABSSASigningKeyModel) {
            self.model = model
            self.verificationKey = VerificationKey(model: model.verificationKey)
        }
    }
}
