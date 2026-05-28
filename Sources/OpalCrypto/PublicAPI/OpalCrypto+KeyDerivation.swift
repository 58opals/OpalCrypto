// OpalCrypto+KeyDerivation.swift

import Foundation
import OpalDiagnostics

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
                OpalDiagnostics.Field.operationField("pbkdf2_derive"),
                OpalDiagnostics.Field.publicField("password_byte_count", password.count),
                OpalDiagnostics.Field.publicField("salt_byte_count", salt.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("iteration_count", iterationCount),
                OpalDiagnostics.Field.publicField("requested_derived_key_byte_count", resolvedDerivedKeyLength),
                OpalDiagnostics.Field.publicField("has_explicit_derived_key_length", derivedKeyLength != nil)
            ]
            do {
                let derivedKey = try PasswordBasedKeyDerivationFunction2Model(
                    password: password,
                    salt: salt.rawRepresentation,
                    iterationCount: iterationCount,
                    derivedKeyLength: derivedKeyLength
                ).deriveKey()
                let parsedDerivedKey = try DerivedKey(rawRepresentation: derivedKey)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.keyDerivation).record(
                    event: OpalDiagnostics.Event.pbkdf2DeriveSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pbkdf2DeriveSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.outputLengthField(parsedDerivedKey.rawRepresentation.count)
                    ]
                )
                return parsedDerivedKey
            } catch let error as PasswordBasedKeyDerivationFunction2Model.Error {
                let mappedError = mapError(error)
                recordDeriveFailed(mappedError, fields: fields)
                throw mappedError
            } catch let error as Error {
                recordDeriveFailed(error, fields: fields)
                throw error
            }
        }

        private static func recordDeriveFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.keyDerivation).record(
                event: OpalDiagnostics.Event.pbkdf2DeriveFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.pbkdf2DeriveFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
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
