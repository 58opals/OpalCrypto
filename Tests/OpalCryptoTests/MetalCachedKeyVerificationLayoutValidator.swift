// MetalCachedKeyVerificationLayoutValidator.swift

import Testing
@testable import OpalCrypto

@Suite("Metal cached-key verification layout validation")
struct MetalCachedKeyVerificationLayoutValidator {
    @Test("Benchmark table bridge reuses production cached-key words")
    func reuseProductionCachedKeyWords() throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(73).makeSigningKey()
        let verificationKey = signingKey.verificationKey
        let context = MetalSchnorrBatchInputPreparationOperation.makeCachedKeyContext(
            verificationKey: verificationKey
        )
        let benchmarkTableWords = PerformanceBenchmarkOperations
            .makeMetalSchnorrVerificationTableWords(verificationKey: verificationKey)
        let sharedWordCount = MetalSchnorrBatchInputPreparationOperation
            .sharedGeneratorTableWordCount

        #expect(
            context.tableWords.count
                == MetalSchnorrBatchInputPreparationOperation.cachedTableWordCount
        )
        #expect(context.tableWords == benchmarkTableWords)
        #expect(
            Array(context.tableWords.prefix(sharedWordCount))
                == MetalSchnorrBatchInputPreparationOperation.sharedGeneratorTableWords
        )
    }
}
