// MosaicPrivateAlphaRSABSSASigningKeyValidator.swift

import Foundation
import Security
@_spi(MosaicPrivateAlpha) @testable import OpalCrypto
import Testing

@Suite("Mosaic private-alpha RSABSSA signing-key restoration")
struct MosaicPrivateAlphaRSABSSASigningKeyValidator {
    typealias RSABSSA = OpalCrypto.RSABSSA

    @Test("Restore the exact app-owned key without replacing its identity")
    func restoreExactAppOwnedKey() throws {
        let generatedModel = try RSABSSASigningKeyModel.generate()
        let securityKey = generatedModel.securityKey.perform { $0 }
        let expectedVerificationKey = RSABSSA.VerificationKey(
            model: generatedModel.verificationKey
        )

        let initiallyValidatedKey = try RSABSSA.SigningKey(
            appOwnedSecurityKey: securityKey
        )
        #expect(
            initiallyValidatedKey.verificationKey
                == expectedVerificationKey
        )

        let restoredKey = try RSABSSA.SigningKey(
            restoring: securityKey,
            matching: expectedVerificationKey
        )

        #expect(restoredKey.verificationKey == expectedVerificationKey)

        let message = Data("restored Mosaic conductor".utf8)
        let request = try RSABSSA.makeBlindRequest(
            message: message,
            using: expectedVerificationKey
        )
        let blindSignature = try restoredKey.blindSign(
            request.blindedMessage
        )
        let signature = try request.finalize(
            blindSignature,
            using: expectedVerificationKey
        )

        #expect(
            signature.verify(
                message: message,
                messageRandomizer: request.messageRandomizer,
                using: expectedVerificationKey
            )
        )
    }

    @Test("Reject a restored key that does not match the attempt manifest")
    func rejectMismatchedAttemptKey() throws {
        let generatedModel = try RSABSSASigningKeyModel.generate()
        let securityKey = generatedModel.securityKey.perform { $0 }
        let otherVerificationKey = try RSABSSA.SigningKey.generate()
            .verificationKey

        #expect(throws: RSABSSA.Error.verificationKeyMismatch) {
            _ = try RSABSSA.SigningKey(
                restoring: securityKey,
                matching: otherVerificationKey
            )
        }
    }

    @Test("Reject a public key in place of the restored signing capability")
    func rejectPublicKey() throws {
        let generatedModel = try RSABSSASigningKeyModel.generate()
        let securityKey = generatedModel.securityKey.perform { $0 }
        let publicKey = try #require(SecKeyCopyPublicKey(securityKey))
        let expectedVerificationKey = RSABSSA.VerificationKey(
            model: generatedModel.verificationKey
        )

        #expect(throws: RSABSSA.Error.unsupportedKeyOperation) {
            _ = try RSABSSA.SigningKey(
                appOwnedSecurityKey: publicKey
            )
        }
        #expect(throws: RSABSSA.Error.unsupportedKeyOperation) {
            _ = try RSABSSA.SigningKey(
                restoring: publicKey,
                matching: expectedVerificationKey
            )
        }
    }
}
