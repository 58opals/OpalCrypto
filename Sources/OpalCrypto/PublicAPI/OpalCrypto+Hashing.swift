// OpalCrypto+Hashing.swift

import Foundation

extension OpalCrypto {
    public enum Hashing {
        public static func computeSHA256(_ data: Data) -> Data {
            SecureHashAlgorithm256Model.hash(data)
        }

        public static func computeHash256(_ data: Data) -> Data {
            SecureHash256Model.hash(data)
        }

        public static func computeHash160(_ data: Data) -> Data {
            SecureHash160Model.hash(data)
        }

        public static func computeHMACSHA512(data: Data, key: Data) -> Data {
            HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.hash(data, key: key)
        }

        public static func computeHMACSHA256(data: Data, key: Data) -> Data {
            HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model.hash(data, key: key)
        }
    }
}
