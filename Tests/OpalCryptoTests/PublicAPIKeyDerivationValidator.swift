// PublicAPIKeyDerivationValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API key-derivation validation")
struct PublicAPIKeyDerivationValidator {
    @Test("Reject invalid PBKDF2 parameters through facade errors")
    func rejectInvalidPbkdf2ParametersThroughFacadeErrors() {
        let invalidCases: [(Int, Int?, Data, OpalCrypto.KeyDerivation.Error)] = [
            (0, 32, Data("salt".utf8), .invalidIterationCount(actual: 0)),
            (-1, 32, Data("salt".utf8), .invalidIterationCount(actual: -1)),
            (16, 0, Data("salt".utf8), .invalidDerivedKeyLength(actual: 0)),
            (16, -1, Data("salt".utf8), .invalidDerivedKeyLength(actual: -1)),
            (16, 32, Data(), .emptySalt)
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

    @Test("Reject PBKDF2 key lengths beyond the RFC maximum")
    func rejectPbkdf2KeyLengthsBeyondTheRfcMaximum() {
        let maximumDerivedKeyLength = Int(UInt64(UInt32.max) * 64)
        let oversizedDerivedKeyLength = maximumDerivedKeyLength + 1

        do {
            _ = try OpalCrypto.KeyDerivation.derivePBKDF2Key(
                password: Data("password".utf8),
                salt: Data("salt".utf8),
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
