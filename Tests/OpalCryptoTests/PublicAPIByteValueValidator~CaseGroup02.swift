// PublicAPIByteValueValidator~CaseGroup02.swift

import Foundation
import Testing
import OpalCrypto

extension PublicAPIByteValueValidator {
    @Test("Pedersen byte values reject malformed raw representations")
    func pedersenByteValuesRejectMalformedRawRepresentations() throws {
        #expect(throws: OpalCrypto.Pedersen.Error.invalidNonceLength(expected: 32, actual: 31)) {
            _ = try OpalCrypto.Pedersen.Nonce(rawRepresentation: Data(repeating: 0x01, count: 31))
        }

        #expect(throws: OpalCrypto.Pedersen.Error.invalidNonce) {
            _ = try OpalCrypto.Pedersen.Nonce(rawRepresentation: Data(repeating: 0xff, count: 32))
        }

        #expect(throws: OpalCrypto.Pedersen.Error.invalidCommitmentLength(actual: 32)) {
            _ = try OpalCrypto.Pedersen.CommitmentPoint(rawRepresentation: Data(repeating: 0x01, count: 32))
        }
    }

    @Test("Key, derivation, and encoding byte values reject malformed raw representations")
    func keyDerivationAndEncodingByteValuesRejectMalformedRawRepresentations() throws {
        #expect(throws: OpalCrypto.Key.ExtendedPrivate.Error.invalidSeedLength(actual: 15)) {
            _ = try OpalCrypto.Key.Seed(rawRepresentation: Data(repeating: 0x01, count: 15))
        }

        #expect(throws: OpalCrypto.Key.ExtendedPrivate.Error.invalidChainCodeLength(expected: 32, actual: 31)) {
            _ = try OpalCrypto.Key.ChainCode(rawRepresentation: Data(repeating: 0x01, count: 31))
        }

        #expect(throws: OpalCrypto.Key.ExtendedPrivate.Error.invalidParentFingerprintLength(expected: 4, actual: 3)) {
            _ = try OpalCrypto.Key.Fingerprint(rawRepresentation: Data(repeating: 0x01, count: 3))
        }

        #expect(throws: OpalCrypto.KeyDerivation.Error.emptySalt) {
            _ = try OpalCrypto.KeyDerivation.Salt(rawRepresentation: Data())
        }

        #expect(throws: OpalCrypto.KeyDerivation.Error.invalidDerivedKeyLength(actual: 0)) {
            _ = try OpalCrypto.KeyDerivation.DerivedKey(rawRepresentation: Data())
        }

        #expect(throws: OpalCrypto.Encoding.Error.invalidFiveBitValue(actual: 0x20)) {
            _ = try OpalCrypto.Encoding.FiveBitValues(rawRepresentation: Data([0x01, 0x20, 0x02]))
        }
    }
}
