// OpalCrypto+KeyDerivation.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto {
    public enum KeyDerivation {

        /// Derives a key with PBKDF2 using HMAC-SHA-512.
        ///
        /// This compatibility entry point uses the same algorithm as
        /// ``derivePBKDF2SHA512Key(password:salt:iterationCount:derivedKeyLength:maximumWorkUnitCount:)``.
        /// Prefer that explicitly named operation in new code.
        ///
        /// - Parameter derivedKeyLength: The requested byte count, or `nil` for
        ///   the default 64-byte output.
        /// - Parameter maximumWorkUnitCount: The maximum number of HMAC
        ///   evaluations the caller permits.
        /// - Throws: ``OpalCrypto/KeyDerivation/Error`` when the salt, iteration
        ///   count, requested length, or work budget is invalid, or
        ///   `CancellationError` when the current task is cancelled during
        ///   derivation.
        public static func derivePBKDF2Key(
            password: Data,
            salt: Salt,
            iterationCount: Int,
            derivedKeyLength: Int? = nil,
            maximumWorkUnitCount: UInt64
        ) throws -> DerivedKey {
            try derivePBKDF2SHA512Key(
                password: password,
                salt: salt,
                iterationCount: iterationCount,
                derivedKeyLength: derivedKeyLength,
                maximumWorkUnitCount: maximumWorkUnitCount
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
        ///   - maximumWorkUnitCount: The maximum number of HMAC evaluations the
        ///     caller permits. Deriving one block consumes `iterationCount`
        ///     work units.
        /// - Returns: A key containing exactly `derivedKeyLength` bytes, or 64
        ///   bytes when the argument is omitted.
        /// - Throws: ``OpalCrypto/KeyDerivation/Error`` when the salt, iteration
        ///   count, requested length, or work budget is invalid, or
        ///   `CancellationError` when the current task is cancelled during
        ///   derivation.
        public static func derivePBKDF2SHA512Key(
            password: Data,
            salt: Salt,
            iterationCount: Int,
            derivedKeyLength: Int? = nil,
            maximumWorkUnitCount: UInt64
        ) throws -> DerivedKey {
            let resolvedDerivedKeyLength = derivedKeyLength
                ?? PasswordBasedKeyDerivationFunction2Model.defaultDerivedKeyLength
            let fields = [
                OpalDiagnostics.Field.operationField("pbkdf2_derive"),
                OpalDiagnostics.Field.publicField("password_byte_count", password.count),
                OpalDiagnostics.Field.publicField("salt_byte_count", salt.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("iteration_count", iterationCount),
                OpalDiagnostics.Field.publicField("requested_derived_key_byte_count", resolvedDerivedKeyLength),
                OpalDiagnostics.Field.publicField("has_explicit_derived_key_length", derivedKeyLength != nil),
                OpalDiagnostics.Field.publicField(
                    "maximum_work_unit_count",
                    String(maximumWorkUnitCount)
                )
            ]
            do {
                let derivedKey = try PasswordBasedKeyDerivationFunction2Model(
                    password: password,
                    salt: salt.rawRepresentation,
                    iterationCount: iterationCount,
                    derivedKeyLength: derivedKeyLength,
                    maximumWorkUnitCount: maximumWorkUnitCount
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
            case .workBudgetExceeded(
                let requiredWorkUnitCount,
                let maximumWorkUnitCount
            ):
                return .workBudgetExceeded(
                    requiredWorkUnitCount: requiredWorkUnitCount,
                    maximumWorkUnitCount: maximumWorkUnitCount
                )
            case .workUnitCountOverflow:
                return .workUnitCountOverflow
            }
        }
    }
}
