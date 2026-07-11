// PublicAPIECDSASignatureValidator~SHA256Contract.swift

import Foundation
import Testing
@testable import OpalCrypto

extension PublicAPIECDSASignatureValidator {
    @Test("Explicit SHA-256 ECDSA operations match source-compatible message operations")
    func matchExplicitSHA256ECDSAOperationsWithSourceCompatibleMessageOperations() throws {
        let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(1)
        let message = Data("opal-explicit-sha256-message".utf8)
        let publicKey = try OpalCrypto.Secp256k1.derivePublicKey(from: privateKey)
        let verificationKey = OpalCrypto.Signature.VerificationKey(publicKey: publicKey)
        let signingKey = privateKey.makeSigningKey()
        let explicitSignature = try OpalCrypto.Signature.ECDSA.signSHA256(
            message: message,
            privateKey: privateKey,
            format: .raw
        )
        let sourceCompatibleSignature = try OpalCrypto.Signature.ECDSA.sign(
            message: message,
            privateKey: privateKey,
            format: .raw
        )
        let explicitSigningKeySignature = try signingKey.signECDSASHA256(
            message: message,
            format: .raw
        )
        let sourceCompatibleSigningKeySignature = try signingKey.signECDSA(
            message: message,
            format: .raw
        )

        #expect(explicitSignature == sourceCompatibleSignature)
        #expect(explicitSigningKeySignature == explicitSignature)
        #expect(sourceCompatibleSigningKeySignature == explicitSignature)
        #expect(try explicitSignature.verifySHA256(message: message, publicKey: publicKey))
        #expect(try explicitSignature.verifySHA256(message: message, verificationKey: verificationKey))
        #expect(try explicitSignature.verify(message: message, verificationKey: verificationKey))
    }
}
