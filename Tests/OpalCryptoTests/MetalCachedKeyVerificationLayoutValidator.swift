// MetalCachedKeyVerificationLayoutValidator.swift

import Testing
@testable import OpalCrypto

@Suite("Metal cached-key verification layout validation")
struct MetalCachedKeyVerificationLayoutValidator {
    @Test("Cached-key preparation reuses byte-identical shared generator words")
    func reuseByteIdenticalSharedGeneratorWords() throws {
        let signingKey = try OpalCryptoTestSupport.makeTypedPrivateKey(73).makeSigningKey()
        let verificationKey = signingKey.verificationKey
        let context = MetalSchnorrBatchInputPreparationOperation.makeCachedKeyContext(
            verificationKey: verificationKey
        )
        let independentlyPreparedWords = PerformanceBenchmarkOperations
            .makeMetalSchnorrVerificationTableWords(verificationKey: verificationKey)
        let sharedWordCount = MetalSchnorrBatchInputPreparationOperation
            .sharedGeneratorTableWordCount

        #expect(
            context.tableWords.count
                == MetalSchnorrBatchInputPreparationOperation.cachedTableWordCount
        )
        #expect(context.tableWords == independentlyPreparedWords)
        #expect(
            Array(context.tableWords.prefix(sharedWordCount))
                == MetalSchnorrBatchInputPreparationOperation.sharedGeneratorTableWords
        )
    }
}
