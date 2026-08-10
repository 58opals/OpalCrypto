// PublicAPIRSABSSAOperationValidator.swift

import Foundation
@testable import OpalCrypto
import Testing

@Suite("OpalCrypto.RSABSSA operations")
struct PublicAPIRSABSSAOperationValidator {
    typealias RSABSSA = OpalCrypto.RSABSSA

    @Test("Generate and reimport the exact PSS verification-key profile")
    func generateAndReimportVerificationKey() throws {
        let signingKey = try RSABSSA.SigningKey.generate()
        let verificationKey = signingKey.verificationKey
        let importedKey = try RSABSSA.VerificationKey(
            subjectPublicKeyInfo: verificationKey.subjectPublicKeyInfo
        )

        #expect(verificationKey.subjectPublicKeyInfo.count == 342)
        #expect(
            verificationKey.keyIdentifier
                == OpalCrypto.Hashing.sha256(
                    verificationKey.subjectPublicKeyInfo
                )
        )
        #expect(importedKey == verificationKey)
        #expect(importedKey.rawRepresentation == verificationKey.rawRepresentation)
        #expect(
            signingKey.description
                == "OpalCrypto.RSABSSA.SigningKey(redacted, variant: RSABSSA-SHA384-PSS-Randomized)"
        )
        #expect(signingKey.debugDescription == signingKey.description)
        requireSendable(signingKey)
        requireSendable(verificationKey)
    }

    @Test("Reject invalid deterministic blinding inputs")
    func rejectInvalidDeterministicBlindingInputs() throws {
        let verificationKey = try RSABSSA.SigningKey.generate()
            .verificationKey.model

        #expect(
            throws: RSABSSA.Error.invalidMessageRandomizerLength(
                expected: 32,
                actual: 31
            )
        ) {
            _ = try RSABSSAModel.makeBlindRequest(
                message: Data(),
                verificationKey: verificationKey,
                messageRandomizer: Data(repeating: 0, count: 31),
                salt: Data(repeating: 0, count: 48),
                blindingFactor: Data(repeating: 1, count: 256)
            )
        }

        #expect(throws: RSABSSA.Error.invalidMessageRepresentative) {
            _ = try RSABSSAModel.makeBlindRequest(
                message: Data(),
                verificationKey: verificationKey,
                messageRandomizer: Data(repeating: 0, count: 32),
                salt: Data(repeating: 0, count: 47),
                blindingFactor: Data(repeating: 1, count: 256)
            )
        }

        #expect(throws: RSABSSA.Error.blindingFailed) {
            _ = try RSABSSAModel.makeBlindRequest(
                message: Data(),
                verificationKey: verificationKey,
                messageRandomizer: Data(repeating: 0, count: 32),
                salt: Data(repeating: 0, count: 48),
                blindingFactor: Data(repeating: 0, count: 256)
            )
        }

        #expect(throws: RSABSSA.Error.invalidMessageRepresentative) {
            _ = try RSABSSAModel.encodePSS(
                message: Data(),
                salt: Data(repeating: 0, count: 48),
                modulusBitCount: 512
            )
        }
    }

    @Test("Complete randomized blind signing and reject altered token inputs")
    func completeBlindSigningRoundTrip() throws {
        let message = Data("Mosaic authorization input".utf8)
        let signingKey = try RSABSSA.SigningKey.generate()
        let request = try RSABSSA.makeBlindRequest(
            message: message,
            using: signingKey.verificationKey
        )
        let blindSignature = try signingKey.blindSign(request.blindedMessage)
        let signature = try request.finalize(
            blindSignature,
            using: signingKey.verificationKey
        )

        #expect(
            signature.verify(
                message: message,
                messageRandomizer: request.messageRandomizer,
                using: signingKey.verificationKey
            )
        )
        #expect(
            !signature.verify(
                message: Data("altered".utf8),
                messageRandomizer: request.messageRandomizer,
                using: signingKey.verificationKey
            )
        )

        var alteredRandomizer = request.messageRandomizer.rawRepresentation
        alteredRandomizer[alteredRandomizer.startIndex] ^= 0x01
        #expect(
            !signature.verify(
                message: message,
                messageRandomizer: try .init(
                    rawRepresentation: alteredRandomizer
                ),
                using: signingKey.verificationKey
            )
        )
    }

    @Test(
        "Complete two purpose-separated maximum-size Mosaic authorization batches",
        .timeLimit(.minutes(5))
    )
    func completeMaximumMosaicAuthorizationBatch() throws {
        let signingKeys = [
            try RSABSSA.SigningKey.generate(),
            try RSABSSA.SigningKey.generate(),
        ]
        #expect(
            signingKeys[0].verificationKey.keyIdentifier
                != signingKeys[1].verificationKey.keyIdentifier
        )

        for (purposeIndex, signingKey) in signingKeys.enumerated() {
            for memberIndex in 0 ..< 184 {
                let message = Data([
                    UInt8(purposeIndex),
                    UInt8(truncatingIfNeeded: memberIndex >> 8),
                    UInt8(truncatingIfNeeded: memberIndex),
                ])
                let request = try RSABSSA.makeBlindRequest(
                    message: message,
                    using: signingKey.verificationKey
                )
                let blindSignature: RSABSSA.BlindSignature
                do {
                    blindSignature = try signingKey.blindSign(
                        request.blindedMessage
                    )
                } catch {
                    Issue.record(
                        "Blind signing failed for purpose \(purposeIndex), member \(memberIndex): \(error)"
                    )
                    throw error
                }
                let signature = try request.finalize(
                    blindSignature,
                    using: signingKey.verificationKey
                )
                #expect(
                    signature.verify(
                        message: message,
                        messageRandomizer: request.messageRandomizer,
                        using: signingKey.verificationKey
                    )
                )
            }
        }
    }

    @Test("Bind finalization to the request verification key")
    func bindFinalizationToVerificationKey() throws {
        let signingKey = try RSABSSA.SigningKey.generate()
        let otherSigningKey = try RSABSSA.SigningKey.generate()
        let request = try RSABSSA.makeBlindRequest(
            message: Data([0x01]),
            using: signingKey.verificationKey
        )
        let blindSignature = try signingKey.blindSign(request.blindedMessage)

        #expect(throws: RSABSSA.Error.verificationKeyMismatch) {
            _ = try request.finalize(
                blindSignature,
                using: otherSigningKey.verificationKey
            )
        }
    }

    @Test("Reject out-of-range signing requests and invalid signer responses")
    func rejectInvalidProtocolValues() throws {
        let signingKey = try RSABSSA.SigningKey.generate()
        let outOfRange = try RSABSSA.BlindedMessage(
            rawRepresentation: Data(repeating: 0xff, count: 256)
        )
        #expect(throws: RSABSSA.Error.messageRepresentativeOutOfRange) {
            _ = try signingKey.blindSign(outOfRange)
        }

        let request = try RSABSSA.makeBlindRequest(
            message: Data([0x02]),
            using: signingKey.verificationKey
        )
        let invalidResponse = try RSABSSA.BlindSignature(
            rawRepresentation: Data(repeating: 0, count: 256)
        )
        #expect(throws: RSABSSA.Error.invalidBlindSignature) {
            _ = try request.finalize(
                invalidResponse,
                using: signingKey.verificationKey
            )
        }
    }

    @Test("Reject malformed or mismatched PSS SubjectPublicKeyInfo")
    func rejectInvalidSubjectPublicKeyInfo() throws {
        let valid = try RSABSSA.SigningKey.generate()
            .verificationKey.subjectPublicKeyInfo

        var wrongAlgorithm = valid
        wrongAlgorithm[15] ^= 0x01
        #expect(throws: RSABSSA.Error.invalidSubjectPublicKeyInfo) {
            _ = try RSABSSA.VerificationKey(
                subjectPublicKeyInfo: wrongAlgorithm
            )
        }

        var trailingData = valid
        trailingData.append(0)
        #expect(throws: RSABSSA.Error.invalidSubjectPublicKeyInfo) {
            _ = try RSABSSA.VerificationKey(
                subjectPublicKeyInfo: trailingData
            )
        }

        let shortModulus = Data([0x80]) + Data(repeating: 0, count: 127)
        let shortKey = RSABSSAKeyEncoding.makeSubjectPublicKeyInfo(
            pkcs1Representation: RSABSSAKeyEncoding.makePKCS1PublicKey(
                modulus: shortModulus,
                publicExponent: 65_537
            )
        )
        #expect(
            throws: RSABSSA.Error.invalidModulusBitCount(
                expected: 2_048,
                actual: 1_024
            )
        ) {
            _ = try RSABSSA.VerificationKey(
                subjectPublicKeyInfo: shortKey
            )
        }

        let profileWidthModulus = Data([0x80])
            + Data(repeating: 0, count: 255)
        let wrongExponentKey = RSABSSAKeyEncoding.makeSubjectPublicKeyInfo(
            pkcs1Representation: RSABSSAKeyEncoding.makePKCS1PublicKey(
                modulus: profileWidthModulus,
                publicExponent: 3
            )
        )
        #expect(
            throws: RSABSSA.Error.invalidPublicExponent(
                expected: 65_537,
                actual: 3
            )
        ) {
            _ = try RSABSSA.VerificationKey(
                subjectPublicKeyInfo: wrongExponentKey
            )
        }
    }

    private func requireSendable<T: Sendable>(_ value: T) {}
}
