// SchnorrSignatureValidator.swift

import Foundation
import CryptoKit
import Testing
@testable import OpalCrypto

@Suite("Schnorr signature validation")
struct SchnorrSignatureValidator {
    @Test("Map public Schnorr nonce policies to their accurate internal behavior")
    func mapPublicSchnorrNoncePoliciesToTheirAccurateInternalBehavior() {
        #expect(
            OpalCrypto.Signature.SchnorrNoncePolicy.bchDeterministic.internalNoncePolicy
                == .requestForComments6979BitcoinCashDefault
        )
        #expect(
            OpalCrypto.Signature.SchnorrNoncePolicy.bchDeterministic.diagnosticsName
                == "bch_deterministic"
        )
        #expect(
            OpalCrypto.Signature.SchnorrNoncePolicy.random.internalNoncePolicy
                == .systemRandom
        )
        #expect(
            OpalCrypto.Signature.SchnorrNoncePolicy.random.diagnosticsName
                == "random"
        )
    }

    @available(*, deprecated, message: "Exercises deprecated source compatibility.")
    @Test("Preserve the legacy behavior of the deprecated BIP-340-named policy")
    func preserveLegacyBehaviorOfDeprecatedBitcoinImprovementProposal340NamedPolicy() {
        #expect(
            OpalCrypto.Signature.SchnorrNoncePolicy.bip340Deterministic.internalNoncePolicy
                == .bitcoinImprovementProposalSchnorrDeterministic
        )
        #expect(
            OpalCrypto.Signature.SchnorrNoncePolicy.bip340Deterministic.diagnosticsName
                == "legacy_bip_schnorr_deterministic"
        )
    }

    @Test("Create signature from sixty-four bytes")
    func createSignatureFromSixtyFourBytes() throws {
        let payload = Data((0..<64).map { UInt8($0) })
        let signature = try SchnorrSignatureModel.Signature(raw64ByteSignatureData: payload)

        #expect(signature.r == Data(payload.prefix(32)))
        #expect(signature.s == Data(payload.suffix(32)))
        #expect(signature.raw64ByteSignatureData == payload)
    }

    @Test("Reject raw signature payload with invalid length")
    func rejectRawSignaturePayloadWithInvalidLength() {
        let payload = Data(repeating: 0xAB, count: 63)
        do {
            _ = try SchnorrSignatureModel.Signature(raw64ByteSignatureData: payload)
            Issue.record("Expected invalid signature length error.")
        } catch let error as SchnorrSignatureModel.Error {
            #expect(error == .invalidSignatureLength(actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject split signature payload with invalid length")
    func rejectSplitSignaturePayloadWithInvalidLength() {
        let signatureRComponent = Data(repeating: 0x01, count: 31)
        let signatureSComponent = Data(repeating: 0x02, count: 32)
        do {
            _ = try SchnorrSignatureModel.Signature(r: signatureRComponent, s: signatureSComponent)
            Issue.record("Expected invalid signature length error.")
        } catch let error as SchnorrSignatureModel.Error {
            #expect(error == .invalidSignatureLength(actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Digest message representation signs the digest directly for Schnorr")
    func digestMessageRepresentationSignsTheDigestDirectlyForSchnorr() throws {
        let privateKey = Data(repeating: 0x00, count: 31) + Data([0x01])
        let digest = SHA256.hash(data: Data("opal-schnorr-digest-message".utf8))
        let message = EllipticCurveDigitalSignatureAlgorithmModel.Message.makeDigest(digest)

        let representedSignature = try EllipticCurveDigitalSignatureAlgorithmModel.sign(
            message: message,
            with: privateKey,
            in: .schnorr,
            nonceFunction: .bitcoinImprovementProposalSchnorrDeterministic
        )
        let directSignature = try SchnorrSignatureModel.sign(
            digestData32Bytes: Data(digest),
            privateKeyData32Bytes: privateKey,
            nonce: .bitcoinImprovementProposalSchnorrDeterministic
        ).raw64ByteSignatureData

        #expect(representedSignature == directSignature)
    }
}
