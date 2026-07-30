// PublicAPISecp256k1Validator~SharedPoint.swift

import Foundation
import Testing
@testable import OpalCrypto

extension PublicAPISecp256k1Validator {
    @Test("Shared-point x reproduces Cash Code reference domains")
    func sharedPointXReproducesCashCodeReferenceDomains() throws {
        let scanPrivateKey = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: makePrivateKey(7)
        )
        let senderPrivateKey = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: makePrivateKey(37)
        )
        let scanPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(
            from: scanPrivateKey
        )
        let senderPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(
            from: senderPrivateKey
        )
        let scanSigningKey = scanPrivateKey.makeSigningKey()
        let senderSigningKey = senderPrivateKey.makeSigningKey()

        let receiverCoordinate =
            OpalCrypto.Secp256k1.deriveSharedPointXCoordinate(
                signingKey: scanSigningKey,
                publicKey: senderPublicKey
            )
        let senderCoordinate =
            OpalCrypto.Secp256k1.deriveSharedPointXCoordinate(
                signingKey: senderSigningKey,
                publicKey: scanPublicKey
            )
        let expectedCoordinate = try Data(
            hexadecimal:
                "c2c80f844b70599812d625460f60340e3e6f36054a14546e6dc25d47376bea9b"
        )

        #expect(receiverCoordinate == senderCoordinate)
        #expect(receiverCoordinate.rawRepresentation == expectedCoordinate)
        #expect(
            OpalCrypto.Secp256k1.deriveSharedPointXCoordinate(
                privateKey: scanPrivateKey,
                publicKey: senderPublicKey
            ) == receiverCoordinate
        )

        var legacyHashInput = Data([0x00])
        legacyHashInput.append(receiverCoordinate.rawRepresentation)
        #expect(
            OpalCrypto.Hashing.sha256(legacyHashInput)
                == (try Data(
                    hexadecimal:
                        "8511bfa62bd512368d50e06b19348f1192a21b1943e01c5f78f633b881a438fe"
                ))
        )

        let currentSharedSecret =
            try OpalCrypto.Secp256k1.deriveSharedSecret(
                privateKey: scanPrivateKey,
                publicKey: senderPublicKey
            )
        #expect(
            currentSharedSecret.rawRepresentation
                == (try Data(
                    hexadecimal:
                        "bda637867435189248ad0e4d0349887aeeceb486a3618e97e838dd5c85bbdff9"
                ))
        )
    }

    @Test("Shared-point x accepts normalized SEC1 input and rejects invalid peers")
    func sharedPointXAcceptsNormalizedSEC1InputAndRejectsInvalidPeers() throws {
        let scanPrivateKey = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: makePrivateKey(7)
        )
        let senderPrivateKey = try OpalCrypto.Secp256k1.PrivateKey(
            rawRepresentation: makePrivateKey(37)
        )
        let compressedSenderPublicKey =
            try OpalCrypto.Secp256k1.derivePublicKey(
                from: senderPrivateKey
            )
        let uncompressedSenderPublicKey =
            try OpalCrypto.Secp256k1.PublicKey(
                rawRepresentation:
                    compressedSenderPublicKey.uncompressedRepresentation
            )

        #expect(
            OpalCrypto.Secp256k1.deriveSharedPointXCoordinate(
                privateKey: scanPrivateKey,
                publicKey: compressedSenderPublicKey
            )
                == OpalCrypto.Secp256k1.deriveSharedPointXCoordinate(
                    privateKey: scanPrivateKey,
                    publicKey: uncompressedSenderPublicKey
                )
        )

        #expect(throws: OpalCrypto.Secp256k1.Error.self) {
            _ = try OpalCrypto.Secp256k1.PublicKey(
                rawRepresentation:
                    Data([0x02]) + Data(repeating: 0xFF, count: 32)
            )
        }
    }
}
