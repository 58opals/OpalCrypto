// OpalCrypto+KeyDerivation.swift

import Foundation

extension OpalCrypto {
    public enum KeyDerivation {
        public static func derivePBKDF2Key(
            password: Data,
            salt: Data,
            iterationCount: Int,
            derivedKeyLength: Int?
        ) throws -> Data {
            try PasswordBasedKeyDerivationFunction2Model(
                password: password,
                salt: salt,
                iterationCount: iterationCount,
                derivedKeyLength: derivedKeyLength
            ).deriveKey()
        }
    }
}
