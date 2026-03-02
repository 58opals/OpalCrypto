import Foundation

extension OpalCryptoFacade {
    public enum KeyDerivation {
        public static func derivePasswordBasedKeyDerivationFunction2Key(
            passwordData: Data,
            saltData: Data,
            iterationCount: Int,
            derivedKeyLength: Int?
        ) throws -> Data {
            try PasswordBasedKeyDerivationFunction2Model(
                password: passwordData,
                salt: saltData,
                iterationCount: iterationCount,
                derivedKeyLength: derivedKeyLength
            ).deriveKey()
        }
    }
}
