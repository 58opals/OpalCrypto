// PublicAPIKeyDerivationValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API key-derivation validation")
struct PublicAPIKeyDerivationValidator {
    @Test("Reject invalid PBKDF2 parameters through facade errors")
    func rejectInvalidPBKDF2ParametersThroughFacadeErrors() {
        let validSalt = try! OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data("salt".utf8))
        let invalidCases: [(Int, Int?, OpalCrypto.KeyDerivation.Salt, OpalCrypto.KeyDerivation.Error)] = [
            (0, 32, validSalt, .invalidIterationCount(actual: 0)),
            (-1, 32, validSalt, .invalidIterationCount(actual: -1)),
            (16, 0, validSalt, .invalidDerivedKeyLength(actual: 0)),
            (16, -1, validSalt, .invalidDerivedKeyLength(actual: -1))
        ]

        for invalidCase in invalidCases {
            do {
                _ = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                    password: Data("password".utf8),
                    salt: invalidCase.2,
                    iterationCount: invalidCase.0,
                    derivedKeyLength: invalidCase.1
                )
                Issue.record("Expected invalid PBKDF2 parameter error.")
            } catch let error as OpalCrypto.KeyDerivation.Error {
                #expect(error == invalidCase.3)
            } catch {
                Issue.record("Unexpected error type: \(error)")
            }
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
