// PublicAPISecp256k1Validator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API secp256k1 validation")
struct PublicAPISecp256k1Validator {
    @Test("Validate private keys and derive compressed public keys")
    func validatePrivateKeysAndDeriveCompressedPublicKeys() throws {
        let zeroPrivateKey = Data(repeating: 0x00, count: 32)
        let onePrivateKey = makePrivateKey(1)

        #expect(!OpalCrypto.Secp256k1.isPrivateKeyValid(zeroPrivateKey))
        #expect(OpalCrypto.Secp256k1.isPrivateKeyValid(onePrivateKey))
        #expect(
            try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: onePrivateKey)
                == Data(hexadecimal: generatorPublicKeyHex)
        )
    }

    @Test("Apply tweak-add to private and public keys consistently")
    func applyTweakAddToPrivateAndPublicKeysConsistently() throws {
        let onePrivateKey = makePrivateKey(1)
        let twoPrivateKey = makePrivateKey(2)
        let tweak = makePrivateKey(1)

        let tweakedPrivateKey = try OpalCrypto.Secp256k1.tweakAddPrivateKey(onePrivateKey, tweak: tweak)
        #expect(tweakedPrivateKey == twoPrivateKey)

        let parentPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: onePrivateKey)
        let expectedPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: twoPrivateKey)
        let tweakedPublicKey = try OpalCrypto.Secp256k1.tweakAddPublicKey(parentPublicKey, tweak: tweak)

        #expect(tweakedPublicKey == expectedPublicKey)
    }

    @Test("Public-key tweak-add accepts uncompressed SEC1 input and still returns compressed output")
    func publicKeyTweakAddAcceptsUncompressedSec1InputAndStillReturnsCompressedOutput() throws {
        let onePrivateKey = makePrivateKey(1)
        let tweak = makePrivateKey(1)

        let compressedPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: onePrivateKey
        )
        let uncompressedPublicKey = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .derivePublicKey(
                fromPrivateKeyData32Bytes: onePrivateKey,
                format: .uncompressed
            )
        let tweakedFromCompressed = try OpalCrypto.Secp256k1.tweakAddPublicKey(
            compressedPublicKey,
            tweak: tweak
        )
        let tweakedFromUncompressed = try OpalCrypto.Secp256k1.tweakAddPublicKey(
            uncompressedPublicKey,
            tweak: tweak
        )

        #expect(tweakedFromUncompressed == tweakedFromCompressed)
    }

    @Test("Shared-secret derivation validates the private key before the public key")
    func sharedSecretDerivationValidatesThePrivateKeyBeforeThePublicKey() {
        do {
            _ = try OpalCrypto.Secp256k1.deriveSharedSecret(
                privateKey: Data(repeating: 0x01, count: 31),
                publicKey: Data(repeating: 0x02, count: 32)
            )
            Issue.record("Expected invalid private-key length error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .invalidPrivateKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Round-trip DER encoding and reject non-canonical DER")
    func roundTripDerEncodingAndRejectNonCanonicalDer() throws {
        let rawSignature = makePrivateKey(1) + makePrivateKey(2)
        let derSignature = try OpalCrypto.Secp256k1.encodeDER(rawSignature)
        #expect(try OpalCrypto.Secp256k1.decodeDER(derSignature) == rawSignature)

        let nonCanonicalDer = Data([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02])
        do {
            _ = try OpalCrypto.Secp256k1.decodeDER(nonCanonicalDer)
            Issue.record("Expected non-canonical DER error.")
        } catch let error as OpalCrypto.Secp256k1.Error {
            #expect(error == .nonCanonicalDER)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Normalize and query low-S signatures")
    func normalizeAndQueryLowSSignatures() throws {
        let highSData = StandardsForEfficientCryptography256k1CurveModel.Constant.n
            .subtractWord(1)
            .data32Bytes
        let rawSignature = makePrivateKey(1) + highSData

        #expect(!(try OpalCrypto.Secp256k1.isLowS(rawSignature)))

        let normalizedSignature = try OpalCrypto.Secp256k1.normalizeLowS(rawSignature)
        #expect(try OpalCrypto.Secp256k1.isLowS(normalizedSignature))
        #expect(Data(normalizedSignature.suffix(32)) == makePrivateKey(1))
    }

    @Test("Batch compressed public-key derivation matches single derivation")
    func batchCompressedPublicKeyDerivationMatchesSingleDerivation() async throws {
        let privateKeys = [1, 2, 3, 4].map(makePrivateKey)
        let batchPublicKeys = try await OpalCrypto.Secp256k1.deriveCompressedPublicKeys(
            from: privateKeys
        )
        let singlePublicKeys = try privateKeys.map {
            try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: $0)
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
