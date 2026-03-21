// PerformanceOptimizationValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Performance optimization validation")
struct PerformanceOptimizationValidator {
    @Test("Batch compressed public-key derivation preserves ordering in the parallel path")
    func batchCompressedPublicKeyDerivationPreservesOrderingInTheParallelPath() async throws {
        let privateKeys = (1...256).map(makePrivateKey)
        let batchPublicKeys = try await OpalCrypto.Secp256k1.deriveCompressedPublicKeys(
            from: privateKeys
        )
        let singlePublicKeys = try privateKeys.map {
            try OpalCrypto.Secp256k1.deriveCompressedPublicKey(from: $0)
        }

        #expect(batchPublicKeys == singlePublicKeys)
    }

    @Test("Parallel mnemonic word-list loads return consistent results")
    func parallelMnemonicWordListLoadsReturnConsistentResults() async throws {
        let wordLists = try await withThrowingTaskGroup(
            of: OpalCrypto.Key.Mnemonic.WordList.self,
            returning: [OpalCrypto.Key.Mnemonic.WordList].self
        ) { group in
            for _ in 0..<8 {
                group.addTask { try OpalCrypto.Key.Mnemonic.WordList.load(.english) }
                group.addTask { try OpalCrypto.Key.Mnemonic.WordList.load(.korean) }
            }

            var resolvedWordLists: [OpalCrypto.Key.Mnemonic.WordList] = []
            for try await wordList in group {
                resolvedWordLists.append(wordList)
            }
            return resolvedWordLists
        }

        let englishWordLists = wordLists.filter { $0.language == .english }
        let koreanWordLists = wordLists.filter { $0.language == .korean }
        let referenceEnglishWordList = try #require(englishWordLists.first)
        let referenceKoreanWordList = try #require(koreanWordLists.first)

        #expect(englishWordLists.count == 8)
        #expect(koreanWordLists.count == 8)
        #expect(englishWordLists.allSatisfy { $0 == referenceEnglishWordList })
        #expect(koreanWordLists.allSatisfy { $0 == referenceKoreanWordList })
    }

    @Test("Internal public-key parsing round-trips compressed and uncompressed encodings")
    func internalPublicKeyParsingRoundTripsCompressedAndUncompressedEncodings() throws {
        let privateKey = makePrivateKey(7)
        let compressedPublicKey = try OpalCrypto.Secp256k1.deriveCompressedPublicKey(
            from: privateKey
        )
        let compressedPoint = try PublicKeyParserModel.parsePublicKey(compressedPublicKey)
        let uncompressedPublicKey = compressedPoint.encodeUncompressed65()
        let uncompressedPoint = try PublicKeyParserModel.parsePublicKey(uncompressedPublicKey)

        #expect(compressedPoint.encodeCompressed33() == compressedPublicKey)
        #expect(uncompressedPoint == compressedPoint)
    }

    private func makePrivateKey(_ value: Int) -> Data {
        var privateKey = Data(repeating: 0x00, count: 32)
        let resolvedValue = UInt32(value)
        privateKey[28] = UInt8((resolvedValue >> 24) & 0xff)
        privateKey[29] = UInt8((resolvedValue >> 16) & 0xff)
        privateKey[30] = UInt8((resolvedValue >> 8) & 0xff)
        privateKey[31] = UInt8(resolvedValue & 0xff)
        return privateKey
    }
}
