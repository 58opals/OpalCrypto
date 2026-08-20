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
                recordDeriveSucceeded(
                    parsedDerivedKey,
                    event: OpalDiagnostics.Event.pbkdf2DeriveSucceeded,
                    fields: fields
                )
                return parsedDerivedKey
            } catch let error as PasswordBasedKeyDerivationFunction2Model.Error {
                let mappedError = mapError(error)
                recordDeriveFailed(
                    mappedError,
                    event: OpalDiagnostics.Event.pbkdf2DeriveFailed,
                    fields: fields
                )
                throw mappedError
            } catch let error as Error {
                recordDeriveFailed(
                    error,
                    event: OpalDiagnostics.Event.pbkdf2DeriveFailed,
                    fields: fields
                )
                throw error
            }
        }

        /// Derives key material with RFC 5869 HKDF using HMAC-SHA-256.
        ///
        /// Empty salt and information values are valid. An empty salt uses the
        /// RFC-defined all-zero SHA-256 salt. HKDF does not add work-factor
        /// hardening and must not be used directly as a password KDF.
        ///
        /// - Parameters:
        ///   - inputKeyMaterial: Source keying material. Diagnostics record only
        ///     its byte count.
        ///   - salt: Independent, non-secret salt bytes, or an empty value for
        ///     the RFC-defined default.
        ///   - information: Context-specific information independent of the
        ///     input keying material.
        ///   - outputByteCount: Requested output length in `1...8160` bytes.
        /// - Returns: The requested derived key material.
        /// - Throws: ``OpalCrypto/KeyDerivation/Error`` when the requested
        ///   output length is invalid or exceeds RFC 5869's SHA-256 limit.
        public static func deriveHKDFSHA256Key(
            inputKeyMaterial: Data,
            salt: Data,
            information: Data,
            outputByteCount: Int
        ) throws -> DerivedKey {
            let fields = [
                OpalDiagnostics.Field.operationField("hkdf_sha256_derive"),
                OpalDiagnostics.Field.publicField(
                    "input_key_material_byte_count",
                    inputKeyMaterial.count
                ),
                OpalDiagnostics.Field.publicField("salt_byte_count", salt.count),
                OpalDiagnostics.Field.publicField("information_byte_count", information.count),
                OpalDiagnostics.Field.publicField(
                    "requested_derived_key_byte_count",
                    outputByteCount
                )
            ]
            do {
                let rawDerivedKey = try
                    HMACBasedKeyDerivationFunctionSecureHashAlgorithm256Model
                        .deriveKey(
                            inputKeyMaterial: inputKeyMaterial,
                            salt: salt,
                            information: information,
                            outputByteCount: outputByteCount
                        )
                let derivedKey = try DerivedKey(rawRepresentation: rawDerivedKey)
                recordDeriveSucceeded(
                    derivedKey,
                    event: OpalDiagnostics.Event.hkdfSHA256DeriveSucceeded,
                    fields: fields
                )
                return derivedKey
            } catch let error as HMACBasedKeyDerivationFunctionSecureHashAlgorithm256Model.Error {
                let mappedError = mapError(error)
                recordDeriveFailed(
                    mappedError,
                    event: OpalDiagnostics.Event.hkdfSHA256DeriveFailed,
                    fields: fields
                )
                throw mappedError
            } catch let error as Error {
                recordDeriveFailed(
                    error,
                    event: OpalDiagnostics.Event.hkdfSHA256DeriveFailed,
                    fields: fields
                )
                throw error
            }
        }

        private static func recordDeriveSucceeded(
            _ derivedKey: DerivedKey,
            event: OpalDiagnostics.Event,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.keyDerivation).record(
                event: event,
                level: .opalCryptoDefault(for: event),
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
            event: OpalDiagnostics.Event,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.keyDerivation).record(
                event: event,
                level: .opalCryptoDefault(for: event),
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

        private static func mapError(
            _ error: HMACBasedKeyDerivationFunctionSecureHashAlgorithm256Model.Error
        ) -> Error {
            switch error {
            case .invalidDerivedKeyLength(let actual):
                return .invalidDerivedKeyLength(actual: actual)
            case .derivedKeyLengthExceedsLimit(let actual):
                return .derivedKeyLengthExceedsLimit(actual: actual)
            }
        }
    }
}
