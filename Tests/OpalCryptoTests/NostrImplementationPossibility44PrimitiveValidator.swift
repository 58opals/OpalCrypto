// NostrImplementationPossibility44PrimitiveValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("NIP-44 version 2 primitive validation")
struct NostrImplementationPossibility44PrimitiveValidator {
    @Test("Match an official NIP-44 message-key vector")
    func matchOfficialMessageKeyVector() throws {
        let conversationKey = try Data(
            hexadecimal:
                "a1a3d60f3470a8612633924e91febf96dc5366ce130f658b1f0fc652c20b3b54"
        )
        let nonce = try Data(
            hexadecimal:
                "e1e6f880560d6d149ed83dcc7e5861ee62a5ee051f7fde9975fe5d25d2a02d72"
        )

        let keys = NostrImplementationPossibility44Model.deriveMessageKeys(
            conversationKey: conversationKey,
            nonce: nonce
        )

        #expect(
            keys.chachaKey == (try Data(
                hexadecimal:
                    "f145f3bed47cb70dbeaac07f3a3fe683e822b3715edb7c4fe310829014ce7d76"
            ))
        )
        #expect(
            keys.chachaNonce == (try Data(
                hexadecimal: "c4ad129bb01180c0933a160c"
            ))
        )
        #expect(
            keys.authenticationKey == (try Data(
                hexadecimal:
                    "027c1db445f05e2eee864a0975b0ddef5b7110583c8c192de3732571ca5838c4"
            ))
        )
    }

    @Test("Match the RFC 8439 ChaCha20 block vector")
    func matchRFC8439ChaCha20BlockVector() throws {
        let key = try Data(
            hexadecimal:
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        )
        let nonce = try Data(hexadecimal: "000000090000004a00000000")
        let expected = try Data(
            hexadecimal:
                "10f1e7e4d13b5915500fdd1fa32071c4"
                + "c7d1f4c733c068030422aa9ac3d46c4e"
                + "d2826446079faa0914c2d705d98b02a2"
                + "b5129cd1de164eb9cbd083e8a2503c4e"
        )

        let block = ChaCha20Model.keyStreamBlock(
            key: [UInt8](key),
            nonce: [UInt8](nonce),
            counter: 1
        )
        #expect(Data(block) == expected)
    }

    @Test(
        "Match the NIP-44 padding buckets",
        arguments: [
            (1, 32), (32, 32), (33, 64), (64, 64), (65, 96),
            (256, 256), (257, 320), (65_535, 65_536),
            (65_536, 65_536), (65_537, 81_920)
        ]
    )
    func matchPaddingBuckets(
        plaintextByteCount: Int,
        expectedPaddedByteCount: Int
    ) {
        #expect(
            NostrImplementationPossibility44Model
                .paddedPlaintextByteCount(plaintextByteCount)
                == expectedPaddedByteCount
        )
    }
}
