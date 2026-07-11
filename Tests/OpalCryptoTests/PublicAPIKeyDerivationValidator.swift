// PublicAPIKeyDerivationValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API key-derivation validation")
struct PublicAPIKeyDerivationValidator {
    @Test("PBKDF2 HMAC-SHA-512 uses a 64-byte default and matches the source-compatible operation")
    func derivePBKDF2SHA512UsingDefaultLength() throws {
        let password = Data("password".utf8)
        let salt = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8))
        let explicitKey = try OpalCrypto.KeyDerivation.derivePBKDF2SHA512Key(
            password: password,
            salt: salt,
            iterationCount: 16
        )
        let sourceCompatibleKey = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
            password: password,
            salt: salt,
            iterationCount: 16
        )

        #expect(explicitKey.rawRepresentation.count == 64)
        #expect(explicitKey == sourceCompatibleKey)
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
                derivedKeyLength: testCase.derivedKeyLength
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
                derivedKeyLength: oversizedDerivedKeyLength
            )
            Issue.record("Expected oversized PBKDF2 key-length error.")
        } catch let error as OpalCrypto.KeyDerivation.Error {
            #expect(error == .derivedKeyLengthExceedsLimit(actual: oversizedDerivedKeyLength))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
