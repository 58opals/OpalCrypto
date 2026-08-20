// OpalCrypto.RSABSSA+SigningKey.swift

import Security

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

        /// Validates a newly created app-owned RSA signing capability before its public key is
        /// bound into a Mosaic attempt document.
        ///
        /// The application owns persistence and access control for `securityKey`. Use the
        /// matching initializer below when restoring a key whose identity is already frozen.
        @_spi(MosaicPrivateAlpha)
        public init(appOwnedSecurityKey securityKey: SecKey) throws {
            self.init(
                model: try RSABSSASigningKeyModel(privateKey: securityKey)
            )
        }

        /// Restores an app-owned RSA signing capability for the exact
        /// verification key published by an existing Mosaic attempt.
        ///
        /// The private key remains inside `SecKey`; this initializer neither
        /// exports private material nor generates replacement material.
        @_spi(MosaicPrivateAlpha)
        public init(
            restoring securityKey: SecKey,
            matching expectedVerificationKey: VerificationKey
        ) throws {
            let model = try RSABSSASigningKeyModel(privateKey: securityKey)
            guard model.verificationKey.subjectPublicKeyInfo
                == expectedVerificationKey.subjectPublicKeyInfo else {
                throw Error.verificationKeyMismatch
            }
            self.init(model: model)
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
