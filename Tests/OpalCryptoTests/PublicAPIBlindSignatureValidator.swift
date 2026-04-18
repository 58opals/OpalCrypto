// PublicAPIBlindSignatureValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API blind signature validation")
struct PublicAPIBlindSignatureValidator {
    @Test("Blind Schnorr requests finalize into valid signatures")
    func blindSchnorrRequestsFinalizeIntoValidSignatures() async throws {
        let privateKey = makeScalar(0x05)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKey
        )
        let signer = try OpalCrypto.BlindSignature.Signer()
        let digest = Data(repeating: 0xAB, count: 32)

        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: digest
        )
        let response = try await signer.sign(
            privateKey: privateKey,
            requestScalar: request.scalar
        )
        let signature = try request.finalize(responseScalar: response)

        #expect(
            try OpalCrypto.Signature.verifySchnorr(
                signature: signature,
                digest: digest,
                publicKey: publicKey
            )
        )
    }

    @Test("Blind signature finalization rejects tampered responses")
    func blindSignatureFinalizationRejectsTamperedResponses() async throws {
        let privateKey = makeScalar(0x06)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKey
        )
        let signer = try OpalCrypto.BlindSignature.Signer()
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: Data(repeating: 0x6C, count: 32)
        )
        let response = try await signer.sign(
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
    func blindSignerRejectsNonceReuse() async throws {
        let privateKey = makeScalar(0x07)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKey
        )
        let signer = try OpalCrypto.BlindSignature.Signer()
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: Data(repeating: 0x7D, count: 32)
        )

        _ = try await signer.sign(privateKey: privateKey, requestScalar: request.scalar)

        do {
            _ = try await signer.sign(privateKey: privateKey, requestScalar: request.scalar)
            Issue.record("Expected nonce reuse rejection.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .nonceAlreadyUsed)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Blind signer aliases share one-time nonce state")
    func blindSignerAliasesShareOneTimeNonceState() async throws {
        let privateKey = makeScalar(0x08)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKey
        )
        let signer = try OpalCrypto.BlindSignature.Signer()
        let signerAlias = signer
        let firstRequest = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: Data(repeating: 0x8E, count: 32)
        )

        _ = try await signer.sign(
            privateKey: privateKey,
            requestScalar: firstRequest.scalar
        )

        let secondRequest = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signerAlias.noncePoint,
            messageDigest: Data(repeating: 0x8F, count: 32)
        )

        do {
            _ = try await signerAlias.sign(
                privateKey: privateKey,
                requestScalar: secondRequest.scalar
            )
            Issue.record("Expected aliased signer to reject nonce reuse.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .nonceAlreadyUsed)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Blind signer keeps nonce available after invalid private-key input")
    func blindSignerKeepsNonceAvailableAfterInvalidPrivateKeyInput() async throws {
        let privateKey = makeScalar(0x09)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKey
        )
        let signer = try OpalCrypto.BlindSignature.Signer()
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: Data(repeating: 0x91, count: 32)
        )

        do {
            _ = try await signer.sign(
                privateKey: Data(repeating: 0x01, count: 31),
                requestScalar: request.scalar
            )
            Issue.record("Expected invalid private-key length rejection.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .invalidPrivateKeyLength(expected: 32, actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        let response = try await signer.sign(
            privateKey: privateKey,
            requestScalar: request.scalar
        )
        let signature = try request.finalize(responseScalar: response)

        #expect(
            try OpalCrypto.Signature.verifySchnorr(
                signature: signature,
                digest: Data(repeating: 0x91, count: 32),
                publicKey: publicKey
            )
        )
    }

    @Test("Blind signer rejects non-canonical request scalars without consuming the nonce")
    func blindSignerRejectsNonCanonicalRequestScalarsWithoutConsumingTheNonce() async throws {
        let privateKey = makeScalar(0x0A)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKey
        )
        let signer = try OpalCrypto.BlindSignature.Signer()
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: Data(repeating: 0xA2, count: 32)
        )

        do {
            _ = try await signer.sign(
                privateKey: privateKey,
                requestScalar: try Data(
                    hexadecimal: """
                    fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
                    """
                )
            )
            Issue.record("Expected malformed request-scalar rejection.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .cryptographyFailure)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        let response = try await signer.sign(
            privateKey: privateKey,
            requestScalar: request.scalar
        )
        let signature = try request.finalize(responseScalar: response)

        #expect(
            try OpalCrypto.Signature.verifySchnorr(
                signature: signature,
                digest: Data(repeating: 0xA2, count: 32),
                publicKey: publicKey
            )
        )
    }

    @Test("Blind request finalization rejects non-canonical response scalars even when verification is disabled")
    func blindRequestFinalizationRejectsNonCanonicalResponseScalarsEvenWhenVerificationIsDisabled()
        async throws {
        let privateKey = makeScalar(0x0B)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(
            fromPrivateKey: privateKey
        )
        let signer = try OpalCrypto.BlindSignature.Signer()
        let request = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: Data(repeating: 0xB3, count: 32)
        )

        do {
            _ = try request.finalize(
                responseScalar: try Data(
                    hexadecimal: """
                    fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
                    """
                ),
                verify: false
            )
            Issue.record("Expected malformed response-scalar rejection.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .cryptographyFailure)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }

        let response = try await signer.sign(
            privateKey: privateKey,
            requestScalar: request.scalar
        )
        let signature = try request.finalize(
            responseScalar: response,
            verify: false
        )

        #expect(
            try OpalCrypto.Signature.verifySchnorr(
                signature: signature,
                digest: Data(repeating: 0xB3, count: 32),
                publicKey: publicKey
            )
        )
    }

    private func makeScalar(_ value: UInt8) -> Data {
        Data(repeating: 0x00, count: 31) + Data([value])
    }
}
