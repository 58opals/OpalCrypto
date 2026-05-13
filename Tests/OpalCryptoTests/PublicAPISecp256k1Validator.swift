// PublicAPISecp256k1Validator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API secp256k1 validation")
struct PublicAPISecp256k1Validator {
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
    func publicKeyConstructionAcceptsUncompressedSec1InputAndNormalizesToCompressedOutput() throws {
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

    @Test("Shared-secret construction normalizes sliced raw input")
    func normalizeSharedSecretConstructionFromSlicedRawInput() throws {
        let sharedSecretData = Data(repeating: 0xAB, count: 32)
        let slicedSharedSecretData = (Data([0xFF]) + sharedSecretData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let sharedSecret = try OpalCrypto.Secp256k1.SharedSecret(
            rawRepresentation: slicedSharedSecretData
        )

        #expect(sharedSecret.rawRepresentation == sharedSecretData)
        #expect(sharedSecret.rawRepresentation.startIndex == 0)
        #expect(sharedSecret.rawRepresentation[0] == 0xAB)
    }

    @Test("Round-trip DER encoding and reject non-canonical DER")
    func roundTripDerEncodingAndRejectNonCanonicalDer() throws {
        let rawSignature = makePrivateKey(1) + makePrivateKey(2)
        let signature = try OpalCrypto.Signature.ECDSA(
            rawRepresentation: rawSignature,
            format: .raw
        )
        let derSignature = try signature.encoded(as: .der)
        #expect(try derSignature.encoded(as: .raw).rawRepresentation == rawSignature)

        let nonCanonicalDer = Data([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02])
        do {
            _ = try OpalCrypto.Signature.ECDSA(rawRepresentation: nonCanonicalDer, format: .der)
            Issue.record("Expected non-canonical DER error.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .nonCanonicalDER)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("DER decoding reports canonical oversized integers as invalid signatures")
    func derDecodingReportsCanonicalOversizedIntegersAsInvalidSignatures() {
        let oversizedR = Data([0x01] + Array(repeating: UInt8(0x00), count: 32))
        let validS = Data([0x01])
        let derSignature = Data([0x30, 0x26, 0x02, 0x21]) + oversizedR + Data([0x02, 0x01]) + validS

        do {
            _ = try OpalCrypto.Signature.ECDSA(rawRepresentation: derSignature, format: .der)
            Issue.record("Expected invalid signature error for oversized DER integer.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignature)
        } catch {
            Issue.record("Unexpected error type for oversized DER integer: \(error)")
        }
    }

    @Test("DER decoding reports canonical negative integers as invalid signatures")
    func derDecodingReportsCanonicalNegativeIntegersAsInvalidSignatures() {
        let derSignature = Data([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01])

        do {
            _ = try OpalCrypto.Signature.ECDSA(rawRepresentation: derSignature, format: .der)
            Issue.record("Expected invalid signature error for negative DER integer.")
        } catch let error as OpalCrypto.Signature.Error {
            #expect(error == .invalidSignature)
        } catch {
            Issue.record("Unexpected error type for negative DER integer: \(error)")
        }
    }

    @Test("Normalize and query low-S signatures")
    func normalizeAndQueryLowSSignatures() throws {
        let highSData = StandardsForEfficientCryptography256k1CurveModel.Constant.n
            .subtractWord(1)
            .data32Bytes
        let rawSignature = makePrivateKey(1) + highSData
        let signature = try OpalCrypto.Signature.ECDSA(rawRepresentation: rawSignature, format: .raw)

        #expect(!signature.isLowS)

        let normalizedSignature = try signature.normalizedLowS()
        #expect(normalizedSignature.isLowS)
        #expect(Data(normalizedSignature.rawRepresentation.suffix(32)) == makePrivateKey(1))
    }

    @Test("Batch public-key derivation matches single derivation")
    func batchPublicKeyDerivationMatchesSingleDerivation() async throws {
        let privateKeys = try [1, 2, 3, 4].map {
            try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: makePrivateKey($0))
        }
        let batchPublicKeys = try await OpalCrypto.Secp256k1.derivePublicKeys(
            from: privateKeys
        )
        let singlePublicKeys = try privateKeys.map {
            try OpalCrypto.Secp256k1.derivePublicKey(from: $0)
        }

        #expect(batchPublicKeys == singlePublicKeys)
    }

    private let generatorPublicKeyHex = """
    0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    """

    private func makePrivateKey(_ value: UInt8) -> Data {
        Data(repeating: 0x00, count: 31) + Data([value])
    }
}
