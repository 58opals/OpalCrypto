// OpalCrypto+KeyDerivation.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto {
    public enum KeyDerivation {

        /// Derives a key with PBKDF2 using HMAC-SHA-512.
        ///
        /// This source-compatible entry point uses the same algorithm as
        /// ``derivePBKDF2SHA512Key(password:salt:iterationCount:derivedKeyLength:)``.
        /// Prefer that explicitly named operation in new code.
        ///
        /// - Parameter derivedKeyLength: The requested byte count, or `nil` for
        ///   the default 64-byte output.
        public static func derivePBKDF2Key(
            password: Data,
            salt: Salt,
            iterationCount: Int,
            derivedKeyLength: Int? = nil
        ) throws -> DerivedKey {
            try derivePBKDF2SHA512Key(
                password: password,
                salt: salt,
                iterationCount: iterationCount,
                derivedKeyLength: derivedKeyLength
            )
        }

        /// Derives a key with PBKDF2 using HMAC-SHA-512.
        ///
        /// - Parameters:
        ///   - password: Secret password bytes. Diagnostics record only the byte
        ///     count and never the password material.
        ///   - salt: A nonempty salt value.
        ///   - iterationCount: A positive number of pseudorandom-function rounds.
        ///   - derivedKeyLength: The requested byte count. The default is 64 bytes.
        /// - Returns: A key containing exactly `derivedKeyLength` bytes, or 64
        ///   bytes when the argument is omitted.
        /// - Throws: ``OpalCrypto/KeyDerivation/Error`` when the salt, iteration
        ///   count, or requested length is invalid.
        public static func derivePBKDF2SHA512Key(
            password: Data,
            salt: Salt,
            iterationCount: Int,
            derivedKeyLength: Int? = nil
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
                recordDeriveSucceeded(parsedDerivedKey, fields: fields)
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

        private static func recordDeriveSucceeded(
            _ derivedKey: DerivedKey,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.keyDerivation).record(
                event: OpalDiagnostics.Event.pbkdf2DeriveSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.pbkdf2DeriveSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.outputLengthField(derivedKey.rawRepresentation.count),
                    OpalDiagnostics.Field.publicField(
                        "derived_key_byte_count",
                        derivedKey.rawRepresentation.count
                    )
                ]
            )
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
