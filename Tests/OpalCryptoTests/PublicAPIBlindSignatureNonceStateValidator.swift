// PublicAPIBlindSignatureNonceStateValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Public API blind signature nonce-state validation")
struct PublicAPIBlindSignatureNonceStateValidator {
    @Test("Blind signOnce rejects nonce reuse")
    func rejectBlindSignerNonceReuseThroughSignOnce() async throws {
        let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(7)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let signer = try OpalCrypto.BlindSignature.Signer()
        let request = try makeRequest(publicKey: publicKey, signer: signer, digestByte: 0x7D)

        _ = try await signer.signOnce(privateKey: privateKey, requestScalar: request.scalar)

        do {
            _ = try await signer.signOnce(privateKey: privateKey, requestScalar: request.scalar)
            Issue.record("Expected nonce reuse rejection.")
        } catch let error as OpalCrypto.BlindSignature.Error {
            #expect(error == .nonceAlreadyUsed)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Blind signer aliases share one-time nonce state")
    func blindSignerAliasesShareOneTimeNonceState() async throws {
        let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(8)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let signer = try OpalCrypto.BlindSignature.Signer()
        let signerAlias = signer
        let firstRequest = try makeRequest(publicKey: publicKey, signer: signer, digestByte: 0x8E)

        _ = try await signer.sign(privateKey: privateKey, requestScalar: firstRequest.scalar)

        let secondRequest = try makeRequest(
            publicKey: publicKey,
            signer: signerAlias,
            digestByte: 0x8F
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

    @Test("Blind request state normalizes sliced message digests")
    func normalizeBlindRequestStateMessageDigestsFromSlicedRawInput() throws {
        let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(10)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let signer = try OpalCrypto.BlindSignature.Signer()
        let digestData = Data(repeating: 0xA1, count: 32)
        let slicedDigestData = (Data([0xFF]) + digestData + Data([0xEE]))
            .dropFirst()
            .dropLast()
        let requestState = try BlindSignatureModel.RequestState(
            signerPublicKey: publicKey.rawRepresentation,
            noncePoint: signer.noncePoint.rawRepresentation,
            messageDigest32Bytes: slicedDigestData
        )

        #expect(requestState.messageDigest32Bytes == digestData)
        #expect(requestState.messageDigest32Bytes.startIndex == 0)
        #expect(requestState.messageDigest32Bytes[0] == 0xA1)
    }

    private func makeRequest(
        publicKey: OpalCrypto.Secp256k1.PublicKey,
        signer: OpalCrypto.BlindSignature.Signer,
        digestByte: UInt8
    ) throws -> OpalCrypto.BlindSignature.Request {
        try OpalCrypto.BlindSignature.Request(
            signerPublicKey: publicKey,
            noncePoint: signer.noncePoint,
            messageDigest: OpalCrypto.Signature.Digest(
                rawRepresentation: Data(repeating: digestByte, count: 32)
            )
        )
    }
}
