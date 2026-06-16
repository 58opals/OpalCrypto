// PublicAPIByteValueValidator~CaseGroup02.swift

import Foundation
import Testing
import OpalCrypto

extension PublicAPIByteValueValidator {
    @Test("Pedersen byte values reject malformed raw representations")
    func pedersenByteValuesRejectMalformedRawRepresentations() throws {
        do {
            _ = try OpalCrypto.Pedersen.Nonce(rawRepresentation: Data(repeating: 0x01, count: 31))
            Issue.record("Expected nonce length error.")
        } catch let error as OpalCrypto.Pedersen.Error {
            #expect(error == .invalidNonceLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Pedersen.Nonce(rawRepresentation: Data(repeating: 0xff, count: 32))
            Issue.record("Expected invalid nonce error.")
        } catch let error as OpalCrypto.Pedersen.Error {
            #expect(error == .invalidNonce)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Pedersen.CommitmentPoint(rawRepresentation: Data(repeating: 0x01, count: 32))
            Issue.record("Expected commitment length error.")
        } catch let error as OpalCrypto.Pedersen.Error {
            #expect(error == .invalidCommitmentLength(actual: 32))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Key, derivation, and encoding byte values reject malformed raw representations")
    func keyDerivationAndEncodingByteValuesRejectMalformedRawRepresentations() throws {
        do {
            _ = try OpalCrypto.Key.Seed(rawRepresentation: Data(repeating: 0x01, count: 15))
            Issue.record("Expected seed length error.")
        } catch let error as OpalCrypto.Key.ExtendedPrivate.Error {
            #expect(error == .invalidSeedLength(actual: 15))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Key.ChainCode(rawRepresentation: Data(repeating: 0x01, count: 31))
            Issue.record("Expected chain-code length error.")
        } catch let error as OpalCrypto.Key.ExtendedPrivate.Error {
            #expect(error == .invalidChainCodeLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Key.Fingerprint(rawRepresentation: Data(repeating: 0x01, count: 3))
            Issue.record("Expected fingerprint length error.")
        } catch let error as OpalCrypto.Key.ExtendedPrivate.Error {
            #expect(error == .invalidParentFingerprintLength(expected: 4, actual: 3))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data())
            Issue.record("Expected empty salt error.")
        } catch let error as OpalCrypto.KeyDerivation.Error {
            #expect(error == .emptySalt)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.KeyDerivation.DerivedKey(rawRepresentation: Data())
            Issue.record("Expected derived-key length error.")
        } catch let error as OpalCrypto.KeyDerivation.Error {
            #expect(error == .invalidDerivedKeyLength(actual: 0))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        do {
            _ = try OpalCrypto.Encoding.FiveBitValues(rawRepresentation: Data([0x01, 0x20, 0x02]))
            Issue.record("Expected five-bit value error.")
        } catch let error as OpalCrypto.Encoding.Error {
            #expect(error == .invalidFiveBitValue(actual: 0x20))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
