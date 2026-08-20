// OpalCrypto.AuthenticatedEncryption+AES256GCM.swift

extension OpalCrypto.AuthenticatedEncryption {
    /// AES-256 in Galois/Counter Mode with a 96-bit nonce and 128-bit tag.
    public enum AES256GCM {
        public static let keyByteCount = 32
        public static let nonceByteCount = 12
        public static let authenticationTagByteCount = 16
        public static let minimumCombinedByteCount = nonceByteCount + authenticationTagByteCount
    }
}
