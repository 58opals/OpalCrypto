// PublicAPISecp256k1Validator~CaseGroup01.swift

import Foundation
import Testing
@testable import OpalCrypto

extension PublicAPISecp256k1Validator {
    @Test("Validate private keys and derive public keys")
    func validatePrivateKeysAndDerivePublicKeys() throws {
        do {
            _ = try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: Data(repeating: 0x00, count: 32)
            )
            Issue.record("Expected invalid private-key error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPrivateKey)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        let privateKey = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: makePrivateKey(1)
        )
        #expect(
            try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey).rawRepresentation
                == Data(hexadecimal: generatorPublicKeyHex)
        )
    }

    @Test("Apply tweak-add to private and public keys consistently")
    func applyTweakAddToPrivateAndPublicKeysConsistently() throws {
        let onePrivateKey = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: makePrivateKey(1)
        )
        let twoPrivateKey = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: makePrivateKey(2)
        )
        let tweak = try OpalCrypto.Secp256k1.Scalar(rawRepresentation: makePrivateKey(1))

        let tweakedPrivateKey = try OpalCrypto.Secp256k1.tweakAddPrivateKey(
            onePrivateKey,
            tweak: tweak
        )
        #expect(tweakedPrivateKey == twoPrivateKey)

        let parentPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: onePrivateKey)
        let expectedPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: twoPrivateKey)
        let tweakedPublicKey = try OpalCrypto.Secp256k1.tweakAddPublicKey(
            parentPublicKey,
            tweak: tweak
        )

        #expect(tweakedPublicKey == expectedPublicKey)
    }

    @Test("Public-key construction accepts uncompressed SEC1 input and normalizes to compressed output")
    func validatePublicKeyConstructionAcceptsUncompressedSec1InputAndNormalizesToCompressedOutput() throws {
        let privateKey = makePrivateKey(1)
        let compressedPublicKey = try OpalCrypto.Secp256k1.PublicKey(
            rawRepresentation: try StandardsForEfficientCryptography256k1CurveModel.Operation
                .derivePublicKey(
                    fromPrivateKeyData32Bytes: privateKey,
                    format: .compressed
                )
        )
        let uncompressedPublicKey = try OpalCrypto.Secp256k1.PublicKey(
            rawRepresentation: StandardsForEfficientCryptography256k1CurveModel.Operation
                .derivePublicKey(
                    fromPrivateKeyData32Bytes: privateKey,
                    format: .uncompressed
                )
        )

        #expect(uncompressedPublicKey.rawRepresentation == compressedPublicKey.rawRepresentation)
        #expect(uncompressedPublicKey.uncompressedRepresentation.count == 65)
    }

    @Test("Public-key construction normalizes sliced compressed SEC1 input")
    func publicKeyConstructionNormalizesSlicedCompressedSec1Input() throws {
        let compressedPublicKeyData = try Data(hexadecimal: generatorPublicKeyHex)
        let slicedPublicKeyData = (Data([0xFF]) + compressedPublicKeyData).dropFirst()
        let publicKey = try OpalCrypto.Secp256k1.PublicKey(
            rawRepresentation: slicedPublicKeyData
        )

        #expect(publicKey.rawRepresentation == compressedPublicKeyData)
        #expect(publicKey.rawRepresentation[0] == 0x02)
    }

    @Test("Private-key construction normalizes sliced raw input")
    func privateKeyConstructionNormalizesSlicedRawInput() throws {
        let privateKeyData = makePrivateKey(1)
        let slicedPrivateKeyData = (Data([0xFF]) + privateKeyData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let privateKey = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: slicedPrivateKeyData
        )

        #expect(privateKey.rawRepresentation == privateKeyData)
        #expect(privateKey.rawRepresentation.startIndex == 0)
        #expect(privateKey.rawRepresentation[0] == 0x00)
    }

    @Test("Public-key construction reports the uncompressed expected length for short SEC1 input")
    func validatePublicKeyConstructionReportsTheUncompressedExpectedLengthForShortSec1Input() {
        let truncatedUncompressedPublicKey = Data(
            [0x04] + Array(repeating: 0x11, count: 63)
        )

        do {
            _ = try OpalCrypto.Secp256k1.PublicKey(
                rawRepresentation: truncatedUncompressedPublicKey
            )
            Issue.record("Expected invalid public-key length error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPublicKeyLength(expected: 65, actual: 64))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Public-key construction treats uncompressed prefixes as length declarations")
    func publicKeyConstructionTreatsUncompressedPrefixesAsLengthDeclarations() {
        let severelyTruncatedUncompressedPublicKey = Data(
            [0x04] + Array(repeating: 0x11, count: 32)
        )

        do {
            _ = try OpalCrypto.Secp256k1.PublicKey(
                rawRepresentation: severelyTruncatedUncompressedPublicKey
            )
            Issue.record("Expected invalid public-key length error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPublicKeyLength(expected: 65, actual: 33))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Shared-secret derivation accepts uncompressed SEC1 public keys")
    func sharedSecretDerivationAcceptsUncompressedSec1PublicKeys() throws {
        let privateKeyA = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: makePrivateKey(0x07)
        )
        let privateKeyB = makePrivateKey(0x08)
        let compressedPublicKeyB = try OpalCrypto.Secp256k1.PublicKey(
            rawRepresentation: StandardsForEfficientCryptography256k1CurveModel.Operation
                .derivePublicKey(
                    fromPrivateKeyData32Bytes: privateKeyB,
                    format: .compressed
                )
        )
        let uncompressedPublicKeyB = try OpalCrypto.Secp256k1.PublicKey(
            rawRepresentation: StandardsForEfficientCryptography256k1CurveModel.Operation
                .derivePublicKey(
                    fromPrivateKeyData32Bytes: privateKeyB,
                    format: .uncompressed
                )
        )

        let sharedSecretFromCompressed = try OpalCrypto.Secp256k1.deriveSharedSecret(
            privateKey: privateKeyA,
            publicKey: compressedPublicKeyB
        )
        let sharedSecretFromUncompressed = try OpalCrypto.Secp256k1.deriveSharedSecret(
            privateKey: privateKeyA,
            publicKey: uncompressedPublicKeyB
        )

        #expect(sharedSecretFromUncompressed == sharedSecretFromCompressed)
        #expect(sharedSecretFromCompressed.rawRepresentation.count == 32)
    }
}
