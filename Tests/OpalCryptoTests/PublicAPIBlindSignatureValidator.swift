// PublicAPIBlindSignatureValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API blind signature validation")
struct PublicAPIBlindSignatureValidator {
    @Test("Blind Schnorr requests finalize into valid signatures")
    func blindSchnorrRequestsFinalizeIntoValidSignatures() throws {
        let privateKey = makeScalar(0x05)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKey
        )
        var signer = try OpalCrypto.BlindSignature.Signer()
        let digest = Data(repeating: 0xAB, count: 32)

        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: digest
        )
        let response = try signer.sign(
            privateKey: privateKey,
            requestScalar: request.scalar
        )
        let signature = try request.finalize(responseScalar: response)

        #expect(
            try OpalCrypto.Signature.verify(
                signature: signature,
                message: digest,
                publicKey: publicKey,
                format: .schnorr
            )
        )
    }

    @Test("Blind signature finalization rejects tampered responses")
    func blindSignatureFinalizationRejectsTamperedResponses() throws {
        let privateKey = makeScalar(0x06)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKey
        )
        var signer = try OpalCrypto.BlindSignature.Signer()
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: Data(repeating: 0x6C, count: 32)
        )
        let response = try signer.sign(
            privateKey: privateKey,
            requestScalar: request.scalar
        )
        var tamperedResponse = response
        tamperedResponse[tamperedResponse.index(before: tamperedResponse.endIndex)] ^= 0x01

        do {
            _ = try request.finalize(responseScalar: tamperedResponse)
            Issue.record("Expected blind-signature verification failure.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .verificationFailed)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Blind signer rejects nonce reuse")
    func blindSignerRejectsNonceReuse() throws {
        let privateKey = makeScalar(0x07)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKey
        )
        var signer = try OpalCrypto.BlindSignature.Signer()
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: Data(repeating: 0x7D, count: 32)
        )

        _ = try signer.sign(privateKey: privateKey, requestScalar: request.scalar)

        do {
            _ = try signer.sign(privateKey: privateKey, requestScalar: request.scalar)
            Issue.record("Expected nonce reuse rejection.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .nonceAlreadyUsed)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    private func makeScalar(_ value: UInt8) -> Data {
        Data(repeating: 0x00, count: 31) + Data([value])
    }
}
