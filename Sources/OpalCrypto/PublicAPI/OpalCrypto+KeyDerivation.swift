// OpalCrypto+KeyDerivation.swift

import Foundation

extension OpalCrypto {
    public enum KeyDerivation {

        public static func derivePBKDF2Key(
            password: Data,
            salt: Salt,
            iterationCount: Int,
            derivedKeyLength: Int?
        ) throws -> DerivedKey {
            do {
                let derivedKey = try PasswordBasedKeyDerivationFunction2Model(
                    password: password,
                    salt: salt.rawRepresentation,
                    iterationCount: iterationCount,
                    derivedKeyLength: derivedKeyLength
                ).deriveKey()
                return try DerivedKey(rawRepresentation: derivedKey)
            } catch let error as PasswordBasedKeyDerivationFunction2Model.Error {
                throw mapError(error)
            }
        }

        private static func mapError(_ error: PasswordBasedKeyDerivationFunction2Model.Error) -> Error {
            switch error {
            case .invalidIterationCount(let actual):
                return .invalidIterationCount(actual: actual)
            case .emptySalt:
                return .emptySalt
            case .invalidDerivedKeyLength(let actual):
                return .invalidDerivedKeyLength(actual: actual)
            case .keyLengthExceedsLimit(let actual):
                return .derivedKeyLengthExceedsLimit(actual: actual)
            }
        }
    }
}
