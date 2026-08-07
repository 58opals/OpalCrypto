// OpalCrypto.RSABSSA+VerificationKey.swift

import Foundation

extension OpalCrypto.RSABSSA {
    /// A validated RSA-2048 verification key bound to the supported PSS profile.
    public struct VerificationKey: Sendable, Equatable {
        internal let model: RSABSSAVerificationKeyModel

        /// The canonical DER SubjectPublicKeyInfo document.
        public let subjectPublicKeyInfo: Data

        /// SHA-256 of ``subjectPublicKeyInfo``.
        public let keyIdentifier: Data

        /// The canonical DER SubjectPublicKeyInfo document.
        public var rawRepresentation: Data { subjectPublicKeyInfo }

        /// Validates an RFC 9578-style PSS SubjectPublicKeyInfo document.
        ///
        /// The document must explicitly select RSA-PSS, SHA-384,
        /// MGF1-SHA384, a 48-byte salt, RSA-2048, and exponent 65,537.
        public init(subjectPublicKeyInfo: Data) throws {
            let model = try RSABSSAVerificationKeyModel(
                subjectPublicKeyInfo: subjectPublicKeyInfo
            )
            self.init(model: model)
        }

        internal init(model: RSABSSAVerificationKeyModel) {
            self.model = model
            self.subjectPublicKeyInfo = model.subjectPublicKeyInfo
            self.keyIdentifier = model.keyIdentifier
        }

        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.subjectPublicKeyInfo == rhs.subjectPublicKeyInfo
        }
    }
}
