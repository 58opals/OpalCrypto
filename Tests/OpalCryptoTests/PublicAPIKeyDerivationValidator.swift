// PublicAPIKeyDerivationValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API key-derivation validation")
struct PublicAPIKeyDerivationValidator {
    @Test("HKDF HMAC-SHA-256 matches RFC 5869 test case 1")
    func deriveHKDFSHA256UsingRFC5869TestCase1() throws {
        // RFC 5869 Appendix A.1: https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1
        let derivedKey = try OpalCrypto.KeyDerivation.deriveHKDFSHA256Key(
            inputKeyMaterial: Data(repeating: 0x0B, count: 22),
            salt: Data(hexadecimal: "000102030405060708090a0b0c"),
            information: Data(hexadecimal: "f0f1f2f3f4f5f6f7f8f9"),
            outputByteCount: 42
        )
        let expectedDerivedKey = try Data(
            hexadecimal: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )

        #expect(derivedKey.rawRepresentation == expectedDerivedKey)
    }

    @Test("HKDF HMAC-SHA-256 accepts RFC zero-length salt and information")
    func deriveHKDFSHA256UsingRFC5869ZeroLengthInputs() throws {
        // RFC 5869 Appendix A.3: https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.3
        let derivedKey = try OpalCrypto.KeyDerivation.deriveHKDFSHA256Key(
            inputKeyMaterial: Data(repeating: 0x0B, count: 22),
            salt: Data(),
            information: Data(),
            outputByteCount: 42
        )
        let expectedDerivedKey = try Data(
            hexadecimal: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        )

        #expect(derivedKey.rawRepresentation == expectedDerivedKey)
    }

    @Test("HKDF HMAC-SHA-256 enforces the RFC output-length boundary")
    func enforceHKDFSHA256OutputLengthBoundary() throws {
        let maximumOutput = try OpalCrypto.KeyDerivation.deriveHKDFSHA256Key(
            inputKeyMaterial: Data("input".utf8),
            salt: Data("salt".utf8),
            information: Data("context".utf8),
            outputByteCount: 8_160
        )

        #expect(maximumOutput.rawRepresentation.count == 8_160)
        #expect(
            throws: OpalCrypto.KeyDerivation.Error.invalidDerivedKeyLength(actual: 0)
        ) {
            _ = try OpalCrypto.KeyDerivation.deriveHKDFSHA256Key(
                inputKeyMaterial: Data(),
                salt: Data(),
                information: Data(),
                outputByteCount: 0
            )
        }
        #expect(
            throws: OpalCrypto.KeyDerivation.Error.derivedKeyLengthExceedsLimit(actual: 8_161)
        ) {
            _ = try OpalCrypto.KeyDerivation.deriveHKDFSHA256Key(
                inputKeyMaterial: Data(),
                salt: Data(),
                information: Data(),
                outputByteCount: 8_161
            )
        }
    }

    @Test("PBKDF2 HMAC-SHA-512 uses a 64-byte default and matches the compatibility operation")
    func derivePBKDF2SHA512UsingDefaultLength() throws {
        let password = Data("password".utf8)
        let salt = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8))
        let explicitKey = try OpalCrypto.KeyDerivation.derivePBKDF2SHA512Key(
            password: password,
            salt: salt,
            iterationCount: 16,
            maximumWorkUnitCount: 16
        )
        let compatibilityKey = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
            password: password,
            salt: salt,
            iterationCount: 16,
            maximumWorkUnitCount: 16
        )

        #expect(explicitKey.rawRepresentation.count == 64)
        #expect(explicitKey == compatibilityKey)
    }

    @Test("PBKDF2 derivation cooperatively reports task cancellation")
    func reportPBKDF2TaskCancellationCooperatively() async {
        let derivationTask = Task {
            withUnsafeCurrentTask { task in
                task?.cancel()
            }
            return try OpalCrypto.KeyDerivation.derivePBKDF2SHA512Key(
                password: Data("password".utf8),
                salt: OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8)),
                iterationCount: 16,
                maximumWorkUnitCount: 16
            )
        }

        await #expect(throws: CancellationError.self) {
            _ = try await derivationTask.value
        }
    }

    @Test(
        "Reject invalid PBKDF2 parameters through facade errors",
        arguments: PasswordBasedKeyDerivationInvalidParameterCase.allCases
    )
    func rejectInvalidPBKDF2ParametersThroughFacadeErrors(
        testCase: PasswordBasedKeyDerivationInvalidParameterCase
    ) throws {
        let validSalt = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8))

        do {
            _ = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                password: Data("password".utf8),
                salt: validSalt,
                iterationCount: testCase.iterationCount,
                derivedKeyLength: testCase.derivedKeyLength,
                maximumWorkUnitCount: 16
            )
            Issue.record("Expected invalid PBKDF2 parameter error.")
        } catch let error as OpalCrypto.KeyDerivation.Error {
            #expect(error == testCase.expectedError)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject empty PBKDF2 salt values before derivation")
    func rejectEmptyPBKDF2SaltValuesBeforeDerivation() {
        do {
            _ = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data())
            Issue.record("Expected empty salt error.")
        } catch let error as OpalCrypto.KeyDerivation.Error {
            #expect(error == .emptySalt)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("PBKDF2 salt values normalize sliced raw input")
    func normalizePBKDF2SaltValuesFromSlicedRawInput() throws {
        let saltData = Data("salt".utf8)
        let slicedSaltData = (Data([0xFF]) + saltData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let salt = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: slicedSaltData)

        #expect(salt.rawRepresentation == saltData)
        #expect(salt.rawRepresentation.startIndex == 0)
        #expect(salt.rawRepresentation[0] == UInt8(ascii: "s"))
    }

    @Test("PBKDF2 derived-key values normalize sliced raw input")
    func normalizePBKDF2DerivedKeyValuesFromSlicedRawInput() throws {
        let derivedKeyData = Data("derived-key".utf8)
        let slicedDerivedKeyData = (Data([0xFF]) + derivedKeyData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let derivedKey = try OpalCrypto.KeyDerivation.DerivedKey(
            rawRepresentation: slicedDerivedKeyData
        )

        #expect(derivedKey.rawRepresentation == derivedKeyData)
        #expect(derivedKey.rawRepresentation.startIndex == 0)
        #expect(derivedKey.rawRepresentation[0] == UInt8(ascii: "d"))
    }

    @Test("Reject PBKDF2 key lengths beyond the RFC maximum")
    func rejectPBKDF2KeyLengthsBeyondTheRFCMaximum() {
        let maximumDerivedKeyLength = Int(UInt64(UInt32.max) * 64)
        let oversizedDerivedKeyLength = maximumDerivedKeyLength + 1

        do {
            _ = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                password: Data("password".utf8),
                salt: OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8)),
                iterationCount: 16,
                derivedKeyLength: oversizedDerivedKeyLength,
                maximumWorkUnitCount: UInt64.max
            )
            Issue.record("Expected oversized PBKDF2 key-length error.")
        } catch let error as OpalCrypto.KeyDerivation.Error {
            #expect(error == .derivedKeyLengthExceedsLimit(actual: oversizedDerivedKeyLength))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Allow PBKDF2 derivation at the exact work budget")
    func allowPBKDF2DerivationAtExactWorkBudget() throws {
        let derivedKey = try OpalCrypto.KeyDerivation.derivePBKDF2SHA512Key(
            password: Data("password".utf8),
            salt: OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8)),
            iterationCount: 2,
            derivedKeyLength: 65,
            maximumWorkUnitCount: 4
        )

        #expect(derivedKey.rawRepresentation.count == 65)
    }

    @Test("Reject PBKDF2 derivation beyond the work budget")
    func rejectPBKDF2DerivationBeyondWorkBudget() {
        #expect(
            throws: OpalCrypto.KeyDerivation.Error.workBudgetExceeded(
                requiredWorkUnitCount: 4,
                maximumWorkUnitCount: 3
            )
        ) {
            _ = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                password: Data("password".utf8),
                salt: OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8)),
                iterationCount: 2,
                derivedKeyLength: 65,
                maximumWorkUnitCount: 3
            )
        }
    }

    @Test("Reject PBKDF2 work-unit multiplication overflow")
    func rejectPBKDF2WorkUnitMultiplicationOverflow() {
        let maximumDerivedKeyLength = Int(UInt64(UInt32.max) * 64)

        #expect(throws: OpalCrypto.KeyDerivation.Error.workUnitCountOverflow) {
            _ = try OpalCrypto.KeyDerivation.derivePBKDF2SHA512Key(
                password: Data("password".utf8),
                salt: OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8)),
                iterationCount: Int.max,
                derivedKeyLength: maximumDerivedKeyLength,
                maximumWorkUnitCount: UInt64.max
            )
        }
    }
}
