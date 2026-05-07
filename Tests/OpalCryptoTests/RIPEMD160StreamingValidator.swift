// RIPEMD160StreamingValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("RIPEMD-160 streaming validation")
struct RIPEMD160StreamingValidator {
    @Test("Streaming updates preserve partial block contents across short chunks")
    func streamingUpdatesPreservePartialBlockContentsAcrossShortChunks() {
        let message = Data((0..<80).map(UInt8.init))
        let expectedDigest = RIPEMD160Model.hash(message)

        var streamingDigest = RIPEMD160Model()
        streamingDigest.update(data: Data(message.prefix(10)))
        streamingDigest.update(data: Data(message.dropFirst(10).prefix(20)))
        streamingDigest.update(data: Data(message.dropFirst(30)))

        #expect(streamingDigest.finalize() == expectedDigest)
    }
}
