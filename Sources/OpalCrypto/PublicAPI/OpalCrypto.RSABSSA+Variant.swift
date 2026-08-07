// OpalCrypto.RSABSSA+Variant.swift

extension OpalCrypto.RSABSSA {
    /// A fully specified RSA blind-signature variant.
    public enum Variant: String, CaseIterable, Sendable {
        /// RFC 9474's randomized SHA-384 and RSA-PSS variant.
        case sha384PSSRandomized = "RSABSSA-SHA384-PSS-Randomized"

        /// The randomized-message prefix length in bytes.
        public var messageRandomizerByteCount: Int { 32 }

        /// The SHA-384 digest length in bytes.
        public var messageDigestByteCount: Int { 48 }

        /// The RSA-PSS salt length in bytes.
        public var saltByteCount: Int { 48 }

        /// The RSA modulus size supported by this bounded contract.
        public var modulusBitCount: Int { 2_048 }

        /// The fixed-width encoded RSA message and signature size.
        public var modulusByteCount: Int { 256 }

        /// The public exponent required by the bounded contract.
        public var publicExponent: Int { 65_537 }
    }
}
