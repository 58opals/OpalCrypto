import Foundation

extension OpalCryptoFacade {
    public enum Hashing {
        public static func makeSecureHashAlgorithm256(_ data: Data) -> Data {
            SecureHashAlgorithm256Model.hash(data)
        }

        public static func makeSecureHash256(_ data: Data) -> Data {
            SecureHash256Model.hash(data)
        }

        public static func makeSecureHash160(_ data: Data) -> Data {
            SecureHash160Model.hash(data)
        }

        public static func makeHashBasedMessageAuthenticationCodeSecureHashAlgorithm512(data: Data, key: Data) -> Data {
            HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.hash(data, key: key)
        }
    }
}
