// PerformanceBenchmarkOperations~MetalVerification.swift

import Foundation

package extension PerformanceBenchmarkOperations {
    static var metalSchnorrVaryingVerificationKeyOddMultipleCount: Int {
        MetalSchnorrBatchInputPreparationOperation.varyingKeyOddMultipleCount
    }
    static var metalWindowedNonAdjacentFormComponentCount: Int {
        MetalSchnorrBatchInputPreparationOperation.packedComponentCount
    }
    static var metalWindowedNonAdjacentFormDigitCount: Int {
        MetalSchnorrBatchInputPreparationOperation.packedDigitCount
    }

    static func makeMetalSchnorrVerificationInput(
        signature: OpalCrypto.Signature.Schnorr,
        digest: OpalCrypto.Signature.Digest,
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) throws -> MetalSchnorrVerificationBenchmarkInput {
        let prepared = try MetalSchnorrBatchInputPreparationOperation
            .prepareCachedKeyRecords(
                signatures: [signature],
                digests: [digest],
                inputOffset: 0,
                localRange: 0..<1,
                verificationKeyModel: verificationKey.verificationKeyModel
            )
        let expected = try SchnorrSignatureModel.verify(
            signature: signature.signatureModel,
            digestData32Bytes: digest.rawRepresentation,
            verificationKeyModel: verificationKey.verificationKeyModel
        )
        return MetalSchnorrVerificationBenchmarkInput(
            signatureXWords: prepared.signatureXWords,
            windowedNonAdjacentFormDigits: prepared.packedDigits,
            windowedNonAdjacentFormTableWords: makeMetalSchnorrVerificationTableWords(
                verificationKey: verificationKey
            ),
            expected: expected
        )
    }

    static func makeMetalSchnorrVerificationBatchInput(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        expectedResults: [Bool],
        verificationKey: OpalCrypto.Signature.VerificationKey,
        tableWords: [UInt32]
    ) throws -> MetalSchnorrVerificationBatchBenchmarkInput {
        validateMetalSchnorrInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            expectedResultCount: expectedResults.count
        )
        let range = signatures.indices
        try MetalSchnorrBatchInputPreparationOperation.validateRange(
            range,
            signatureCount: signatures.count,
            digestCount: digests.count
        )
        let prepared = try MetalSchnorrBatchInputPreparationOperation
            .prepareCachedKeyRecords(
                signatures: signatures,
                digests: digests,
                inputOffset: 0,
                localRange: range,
                verificationKeyModel: verificationKey.verificationKeyModel
            )
        return MetalSchnorrVerificationBatchBenchmarkInput(
            recordCount: signatures.count,
            signatureXWords: prepared.signatureXWords,
            windowedNonAdjacentFormDigits: prepared.packedDigits,
            windowedNonAdjacentFormTableWords: tableWords,
            expectedResults: expectedResults.map { $0 ? 1 : 0 }
        )
    }

    static func makeMetalSchnorrVerificationBatchInputParallel(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        expectedResults: [Bool],
        verificationKey: OpalCrypto.Signature.VerificationKey,
        tableWords: [UInt32]
    ) async throws -> MetalSchnorrVerificationBatchBenchmarkInput {
        validateMetalSchnorrInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            expectedResultCount: expectedResults.count
        )
        let context = MetalSchnorrCachedKeyContext(
            verificationKeyModel: verificationKey.verificationKeyModel,
            tableIdentifier: verificationKey.rawRepresentation,
            tableWords: tableWords
        )
        let prepared = try await MetalSchnorrBatchInputPreparationOperation
            .prepareCachedKeyInput(
                signatures: signatures,
                digests: digests,
                range: signatures.indices,
                context: context
            )
        return MetalSchnorrVerificationBatchBenchmarkInput(
            recordCount: prepared.recordCount,
            signatureXWords: prepared.signatureXWords,
            windowedNonAdjacentFormDigits: prepared.packedDigits,
            windowedNonAdjacentFormTableWords: prepared.tableWords,
            expectedResults: expectedResults.map { $0 ? 1 : 0 }
        )
    }

    static func makeMetalSchnorrVaryingKeyVerificationBatchInput(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        expectedResults: [Bool],
        verificationKeys: [OpalCrypto.Signature.VerificationKey]
    ) throws -> MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput {
        try makeMetalSchnorrVaryingKeyVerificationBatchInput(
            signatures: signatures,
            digests: digests,
            expectedResults: expectedResults,
            verificationKeySource: .prepared(verificationKeys)
        )
    }

    static func makeMetalSchnorrVaryingKeyVerificationBatchInput(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        expectedResults: [Bool],
        verificationKeyRawRepresentations: [Data]
    ) throws -> MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput {
        try makeMetalSchnorrVaryingKeyVerificationBatchInput(
            signatures: signatures,
            digests: digests,
            expectedResults: expectedResults,
            verificationKeySource: .rawRepresentations(verificationKeyRawRepresentations)
        )
    }

    static func makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        expectedResults: [Bool],
        verificationKeys: [OpalCrypto.Signature.VerificationKey]
    ) async throws -> MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput {
        try await makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
            signatures: signatures,
            digests: digests,
            expectedResults: expectedResults,
            verificationKeySource: .prepared(verificationKeys)
        )
    }

    static func makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        expectedResults: [Bool],
        verificationKeyRawRepresentations: [Data]
    ) async throws -> MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput {
        try await makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
            signatures: signatures,
            digests: digests,
            expectedResults: expectedResults,
            verificationKeySource: .rawRepresentations(verificationKeyRawRepresentations)
        )
    }

    private static func makeMetalSchnorrVaryingKeyVerificationBatchInput(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        expectedResults: [Bool],
        verificationKeySource: MetalSchnorrVerificationKeySource
    ) throws -> MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput {
        validateMetalSchnorrInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            expectedResultCount: expectedResults.count,
            verificationKeyCount: verificationKeySource.count
        )
        let range = signatures.indices
        try MetalSchnorrBatchInputPreparationOperation.validateRange(
            range,
            signatureCount: signatures.count,
            digestCount: digests.count,
            publicKeyCount: verificationKeySource.count
        )
        let preparedRecords = try MetalSchnorrBatchInputPreparationOperation
            .prepareVaryingKeyRecords(
                signatures: signatures,
                digests: digests,
                verificationKeySource: verificationKeySource,
                inputOffset: 0,
                localRange: range
            )
        let prepared = try MetalSchnorrVaryingKeyBatchInput(
            recordCount: signatures.count,
            signatureXWords: preparedRecords.signatureXWords,
            packedDigits: preparedRecords.packedDigits,
            sharedGeneratorTableWords:
                MetalSchnorrBatchInputPreparationOperation.sharedGeneratorTableWords,
            varyingVerificationKeyTableWords: preparedRecords.tableWords
        )
        return makeMetalSchnorrVaryingKeyVerificationBatchInput(
            prepared: prepared,
            expectedResults: expectedResults
        )
    }

    private static func makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        expectedResults: [Bool],
        verificationKeySource: MetalSchnorrVerificationKeySource
    ) async throws -> MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput {
        validateMetalSchnorrInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            expectedResultCount: expectedResults.count,
            verificationKeyCount: verificationKeySource.count
        )
        let prepared = try await MetalSchnorrBatchInputPreparationOperation
            .prepareVaryingKeyInput(
                signatures: signatures,
                digests: digests,
                verificationKeySource: verificationKeySource,
                range: signatures.indices
            )
        return makeMetalSchnorrVaryingKeyVerificationBatchInput(
            prepared: prepared,
            expectedResults: expectedResults
        )
    }

    private static func makeMetalSchnorrVaryingKeyVerificationBatchInput(
        prepared: MetalSchnorrVaryingKeyBatchInput,
        expectedResults: [Bool]
    ) -> MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput {
        MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput(
            recordCount: prepared.recordCount,
            signatureXWords: prepared.signatureXWords,
            windowedNonAdjacentFormDigits: prepared.packedDigits,
            sharedGeneratorTableWords: prepared.sharedGeneratorTableWords,
            varyingVerificationKeyTableWords: prepared.varyingVerificationKeyTableWords,
            expectedResults: expectedResults.map { $0 ? 1 : 0 }
        )
    }

    static func makeMetalSchnorrVerificationTableWords(
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) -> [UInt32] {
        MetalSchnorrBatchInputPreparationOperation.makeCachedKeyTableWords(
            verificationKeyModel: verificationKey.verificationKeyModel
        )
    }

    static func packMetalWindowedNonAdjacentFormDigits(
        _ recordMajorDigits: [Int8],
        recordCount: Int
    ) -> [Int8] {
        precondition(recordCount >= 0, "Record count cannot be negative.")
        let digitsPerRecord = metalWindowedNonAdjacentFormComponentCount
            * metalWindowedNonAdjacentFormDigitCount
        precondition(
            recordMajorDigits.count == recordCount * digitsPerRecord,
            "Expected one complete WNAF digit record per input record."
        )
        guard recordCount > 0 else { return [] }

        var packedDigits = Array(repeating: Int8.zero, count: recordMajorDigits.count)
        for recordIndex in 0..<recordCount {
            let recordBase = recordIndex * digitsPerRecord
            for component in 0..<metalWindowedNonAdjacentFormComponentCount {
                for digitIndex in 0..<metalWindowedNonAdjacentFormDigitCount {
                    let sourceIndex = recordBase
                        + component * metalWindowedNonAdjacentFormDigitCount
                        + digitIndex
                    let destinationIndex = metalWindowedNonAdjacentFormPackedDigitOffset(
                        recordIndex: recordIndex,
                        component: component,
                        digitIndex: digitIndex,
                        recordCount: recordCount
                    )
                    packedDigits[destinationIndex] = recordMajorDigits[sourceIndex]
                }
            }
        }
        return packedDigits
    }

    static func unpackMetalWindowedNonAdjacentFormDigits(
        _ packedDigits: [Int8],
        recordCount: Int
    ) -> [Int8] {
        precondition(recordCount >= 0, "Record count cannot be negative.")
        let digitsPerRecord = metalWindowedNonAdjacentFormComponentCount
            * metalWindowedNonAdjacentFormDigitCount
        precondition(
            packedDigits.count == recordCount * digitsPerRecord,
            "Expected one complete packed WNAF digit record per input record."
        )
        guard recordCount > 0 else { return [] }

        var recordMajorDigits = Array(repeating: Int8.zero, count: packedDigits.count)
        for recordIndex in 0..<recordCount {
            let recordBase = recordIndex * digitsPerRecord
            for component in 0..<metalWindowedNonAdjacentFormComponentCount {
                for digitIndex in 0..<metalWindowedNonAdjacentFormDigitCount {
                    let destinationIndex = recordBase
                        + component * metalWindowedNonAdjacentFormDigitCount
                        + digitIndex
                    let sourceIndex = metalWindowedNonAdjacentFormPackedDigitOffset(
                        recordIndex: recordIndex,
                        component: component,
                        digitIndex: digitIndex,
                        recordCount: recordCount
                    )
                    recordMajorDigits[destinationIndex] = packedDigits[sourceIndex]
                }
            }
        }
        return recordMajorDigits
    }

    static func metalWindowedNonAdjacentFormPackedDigitOffset(
        recordIndex: Int,
        component: Int,
        digitIndex: Int,
        recordCount: Int
    ) -> Int {
        precondition(recordIndex >= 0 && recordIndex < recordCount)
        precondition(component >= 0 && component < metalWindowedNonAdjacentFormComponentCount)
        precondition(digitIndex >= 0 && digitIndex < metalWindowedNonAdjacentFormDigitCount)
        return (
            component * metalWindowedNonAdjacentFormDigitCount + digitIndex
        ) * recordCount + recordIndex
    }

    static var metalSchnorrSharedGeneratorTableWordCount: Int {
        MetalSchnorrBatchInputPreparationOperation.sharedGeneratorTableWordCount
    }

    static var metalSchnorrVaryingVerificationKeyTableSlotCount: Int {
        MetalSchnorrBatchInputPreparationOperation.varyingKeyTableSlotCount
    }

    static func metalSchnorrVaryingVerificationKeyTableWordOffset(
        recordIndex: Int,
        slotIndex: Int,
        recordCount: Int
    ) -> Int {
        precondition(recordIndex >= 0 && recordIndex < recordCount)
        precondition(
            slotIndex >= 0 && slotIndex < metalSchnorrVaryingVerificationKeyTableSlotCount
        )
        return slotIndex * recordCount + recordIndex
    }

    static func makeMetalFieldValidationCase(
        leftData32: Data,
        rightData32: Data
    ) throws -> MetalFieldValidationBenchmarkCase {
        let left = try FieldElementModel(data32: leftData32)
        let right = try FieldElementModel(data32: rightData32)
        return MetalFieldValidationBenchmarkCase(
            leftWords: littleEndianWords(fromBigEndian32: left.data32Bytes),
            rightWords: littleEndianWords(fromBigEndian32: right.data32Bytes),
            expectedProductWords: littleEndianWords(
                fromBigEndian32: left.mul(right).data32Bytes
            ),
            expectedSquareWords: littleEndianWords(fromBigEndian32: left.square().data32Bytes),
            expectedQuadraticResidue: left.isQuadraticResidue ? 1 : 0
        )
    }

    static func makeMetalSchnorrSharedGeneratorTableWords() -> [UInt32] {
        MetalSchnorrBatchInputPreparationOperation.sharedGeneratorTableWords
    }

    private static func validateMetalSchnorrInputCounts(
        signatureCount: Int,
        digestCount: Int,
        expectedResultCount: Int,
        verificationKeyCount: Int? = nil
    ) {
        precondition(signatureCount == digestCount)
        precondition(signatureCount == expectedResultCount)
        precondition(verificationKeyCount.map { $0 == signatureCount } ?? true)
    }

    private static func littleEndianWords(fromBigEndian32 data: Data) -> [UInt32] {
        precondition(data.count == 32, "Expected exactly 32 bytes.")
        var words: [UInt32] = []
        words.reserveCapacity(8)
        MetalSchnorrBatchInputPreparationOperation.appendLittleEndianWords(
            fromBigEndian32: data,
            to: &words
        )
        return words
    }
}
