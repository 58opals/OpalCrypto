// PublicAPIBlindSignatureNonceStateValidator.swift

import Foundation
import Testing
import OpalCrypto

@Suite("Public API blind signature nonce-state validation")
struct PublicAPIBlindSignatureNonceStateValidator {
    @Test("Blind signer rejects nonce reuse")
    func blindSignerRejectsNonceReuse() async throws {
        let privateKey = OpalCryptoTestSupport.makePrivateKey(7)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKey)
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
        let privateKey = OpalCryptoTestSupport.makePrivateKey(8)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKey)
        let signer = try OpalCrypto.BlindSignature.Signer()
        let signerAlias = signer
        let firstRequest = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: Data(repeating: 0x8E, count: 32)
        )

        _ = try await signer.sign(privateKey: privateKey, requestScalar: firstRequest.scalar)

        let secondRequest = try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signerAlias.noncePoint,
            messageDigest: Data(repeating: 0x8F, count: 32)
        )

        do {
            _ = try await signerAlias.sign(privateKey: privateKey, requestScalar: secondRequest.scalar)
            Issue.record("Expected aliased signer to reject nonce reuse.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .nonceAlreadyUsed)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Blind signer keeps nonce available after invalid private-key input")
    func blindSignerKeepsNonceAvailableAfterInvalidPrivateKeyInput() async throws {
        let privateKey = OpalCryptoTestSupport.makePrivateKey(9)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKey)
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

        let response = try await signer.sign(privateKey: privateKey, requestScalar: request.scalar)
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
        let privateKey = OpalCryptoTestSupport.makePrivateKey(10)
        let publicKey = try OpalCrypto.Signature.derivePublicKey(fromPrivateKey: privateKey)
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

        let response = try await signer.sign(privateKey: privateKey, requestScalar: request.scalar)
        let signature = try request.finalize(responseScalar: response)

        #expect(
            try OpalCrypto.Signature.verifySchnorr(
                signature: signature,
                digest: Data(repeating: 0xA2, count: 32),
                publicKey: publicKey
            )
        )
    }
}
