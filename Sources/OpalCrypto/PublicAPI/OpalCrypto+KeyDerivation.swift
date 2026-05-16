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
            let resolvedDerivedKeyLength = derivedKeyLength
                ?? PasswordBasedKeyDerivationFunction2Model.defaultDerivedKeyLength
            let fields = [
                OpalCryptoDiagnostics.operationField("pbkdf2_derive"),
                OpalCryptoDiagnostics.publicField("salt_byte_count", salt.rawRepresentation.count),
                OpalCryptoDiagnostics.publicField("iteration_count", iterationCount),
                OpalCryptoDiagnostics.publicField("requested_derived_key_byte_count", resolvedDerivedKeyLength),
                OpalCryptoDiagnostics.publicField("has_explicit_derived_key_length", derivedKeyLength != nil)
            ]
            do {
                let derivedKey = try PasswordBasedKeyDerivationFunction2Model(
                    password: password,
                    salt: salt.rawRepresentation,
                    iterationCount: iterationCount,
                    derivedKeyLength: derivedKeyLength
                ).deriveKey()
                let parsedDerivedKey = try DerivedKey(rawRepresentation: derivedKey)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pbkdf2DeriveSucceeded,
                    category: OpalCryptoDiagnostics.Category.keyDerivation,
                    fields: fields + [
                        OpalCryptoDiagnostics.outputLengthField(parsedDerivedKey.rawRepresentation.count)
                    ]
                )
                return parsedDerivedKey
            } catch let error as PasswordBasedKeyDerivationFunction2Model.Error {
                let mappedError = mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pbkdf2DeriveFailed,
                    category: OpalCryptoDiagnostics.Category.keyDerivation,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pbkdf2DeriveFailed,
                    category: OpalCryptoDiagnostics.Category.keyDerivation,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
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
