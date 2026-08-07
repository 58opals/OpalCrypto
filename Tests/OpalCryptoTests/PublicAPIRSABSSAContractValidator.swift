// PublicAPIRSABSSAContractValidator.swift

import Foundation
import OpalCrypto
import Testing

@Suite("OpalCrypto.RSABSSA data contract")
struct PublicAPIRSABSSAContractValidator {
    @Test("Freeze the randomized RSA-2048 SHA-384 variant")
    func freezeRandomizedRSA2048SHA384Variant() {
        let variant = OpalCrypto.RSABSSA.Variant.sha384PSSRandomized

        #expect(variant.rawValue == "RSABSSA-SHA384-PSS-Randomized")
        #expect(variant.messageRandomizerByteCount == 32)
        #expect(variant.messageDigestByteCount == 48)
        #expect(variant.saltByteCount == 48)
        #expect(variant.modulusBitCount == 2_048)
        #expect(variant.modulusByteCount == 256)
        #expect(variant.publicExponent == 65_537)
    }

    @Test("Accept exact-width RSABSSA values")
    func acceptExactWidthValues() throws {
        let randomizerBytes = Data(repeating: 0x11, count: 32)
        let rsaBytes = Data(repeating: 0x22, count: 256)

        let randomizer = try OpalCrypto.RSABSSA.MessageRandomizer(
            rawRepresentation: randomizerBytes
        )
        let blindedMessage = try OpalCrypto.RSABSSA.BlindedMessage(
            rawRepresentation: rsaBytes
        )
        let blindSignature = try OpalCrypto.RSABSSA.BlindSignature(
            rawRepresentation: rsaBytes
        )
        let signature = try OpalCrypto.RSABSSA.Signature(
            rawRepresentation: rsaBytes
        )

        #expect(randomizer.rawRepresentation == randomizerBytes)
        #expect(blindedMessage.rawRepresentation == rsaBytes)
        #expect(blindSignature.rawRepresentation == rsaBytes)
        #expect(signature.rawRepresentation == rsaBytes)
        requireSendable(randomizer)
        requireSendable(blindedMessage)
        requireSendable(blindSignature)
        requireSendable(signature)
    }

    @Test("Reject every invalid RSABSSA width")
    func rejectInvalidWidths() {
        #expect(throws: OpalCrypto.RSABSSA.Error.invalidMessageRandomizerLength(
            expected: 32,
            actual: 31
        )) {
            try OpalCrypto.RSABSSA.MessageRandomizer(
                rawRepresentation: Data(repeating: 0, count: 31)
            )
        }
        #expect(throws: OpalCrypto.RSABSSA.Error.invalidBlindedMessageLength(
            expected: 256,
            actual: 255
        )) {
            try OpalCrypto.RSABSSA.BlindedMessage(
                rawRepresentation: Data(repeating: 0, count: 255)
            )
        }
        #expect(throws: OpalCrypto.RSABSSA.Error.invalidBlindSignatureLength(
            expected: 256,
            actual: 257
        )) {
            try OpalCrypto.RSABSSA.BlindSignature(
                rawRepresentation: Data(repeating: 0, count: 257)
            )
        }
        #expect(throws: OpalCrypto.RSABSSA.Error.invalidSignatureLength(
            expected: 256,
            actual: 0
        )) {
            try OpalCrypto.RSABSSA.Signature(rawRepresentation: Data())
        }
    }

    private func requireSendable<T: Sendable>(_ value: T) {}
}
