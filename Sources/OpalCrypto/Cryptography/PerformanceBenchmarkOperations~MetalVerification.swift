// PerformanceBenchmarkOperations~MetalVerification.swift

import Foundation

package extension PerformanceBenchmarkOperations {
    private static var metalWindowedNonAdjacentFormWidth: Int { 7 }
    private static var metalWindowedNonAdjacentFormOddMultipleCount: Int { 32 }
    static var metalSchnorrVaryingVerificationKeyWindowedNonAdjacentFormWidth: Int { 3 }
    static var metalSchnorrVaryingVerificationKeyOddMultipleCount: Int { 2 }
    static var metalWindowedNonAdjacentFormComponentCount: Int { 4 }
    static var metalWindowedNonAdjacentFormDigitCount: Int { 130 }

    static func makeMetalSchnorrVerificationInput(
        signature: OpalCrypto.Signature.Schnorr,
        digest: OpalCrypto.Signature.Digest,
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) throws -> MetalSchnorrVerificationBenchmarkInput {
        let signatureModel = signature.signatureModel
        let signatureX = try FieldElementModel(data32: signatureModel.r)
        let signatureScalar = try ScalarModel(data32: signatureModel.s)
        let challenge = try ChallengeHashModel.makeChallengeScalar(
            digest32: digest.rawRepresentation,
            r: signatureX,
            verificationKeyModel: verificationKey.verificationKeyModel
        )
        let expected = try SchnorrSignatureModel.verify(
            signature: signatureModel,
            digestData32Bytes: digest.rawRepresentation,
            verificationKeyModel: verificationKey.verificationKeyModel
        )
        let negatedChallenge = challenge.negateModN()
        return MetalSchnorrVerificationBenchmarkInput(
            signatureXWords: Self.littleEndianWords(fromBigEndian32: signatureX.data32Bytes),
            windowedNonAdjacentFormDigits: Self.packMetalWindowedNonAdjacentFormDigits(
                Self.windowedNonAdjacentFormDigits(
                    generatorScalar: signatureScalar,
                    verificationKeyScalar: negatedChallenge
                ),
                recordCount: 1
            ),
            windowedNonAdjacentFormTableWords: Self.makeMetalSchnorrVerificationTableWords(
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
        precondition(signatures.count == digests.count)
        precondition(signatures.count == expectedResults.count)

        var signatureXWords: [UInt32] = .init()
        signatureXWords.reserveCapacity(signatures.count * 8)
        let digitsPerRecord = metalWindowedNonAdjacentFormComponentCount
            * metalWindowedNonAdjacentFormDigitCount
        var packedDigits = Array(
            repeating: Int8.zero,
            count: signatures.count * digitsPerRecord
        )

        for index in signatures.indices {
            let signatureModel = signatures[index].signatureModel
            let signatureX = try FieldElementModel(data32: signatureModel.r)
            let signatureScalar = try ScalarModel(data32: signatureModel.s)
            let challenge = try ChallengeHashModel.makeChallengeScalar(
                digest32: digests[index].rawRepresentation,
                r: signatureX,
                verificationKeyModel: verificationKey.verificationKeyModel
            )
            signatureXWords.append(
                contentsOf: Self.littleEndianWords(fromBigEndian32: signatureX.data32Bytes)
            )
            let recordDigits = Self.windowedNonAdjacentFormDigits(
                generatorScalar: signatureScalar,
                verificationKeyScalar: challenge.negateModN()
            )
            for component in 0..<metalWindowedNonAdjacentFormComponentCount {
                for digitIndex in 0..<metalWindowedNonAdjacentFormDigitCount {
                    packedDigits[
                        metalWindowedNonAdjacentFormPackedDigitOffset(
                            recordIndex: index,
                            component: component,
                            digitIndex: digitIndex,
                            recordCount: signatures.count
                        )
                    ] = recordDigits[
                        component * metalWindowedNonAdjacentFormDigitCount + digitIndex
                    ]
                }
            }
        }

        return MetalSchnorrVerificationBatchBenchmarkInput(
            recordCount: signatures.count,
            signatureXWords: signatureXWords,
            windowedNonAdjacentFormDigits: packedDigits,
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
        precondition(signatures.count == digests.count)
        precondition(signatures.count == expectedResults.count)

        let recordCount = signatures.count
        guard recordCount > 0 else {
            return MetalSchnorrVerificationBatchBenchmarkInput(
                recordCount: 0,
                signatureXWords: [],
                windowedNonAdjacentFormDigits: [],
                windowedNonAdjacentFormTableWords: tableWords,
                expectedResults: []
            )
        }

        let processorCount = max(1, ProcessInfo.processInfo.activeProcessorCount)
        let taskCount = min(
            processorCount,
            max(1, recordCount / minimumMetalSchnorrVerificationRecordsPerTask)
        )
        let baseChunkCount = recordCount / taskCount
        let remainder = recordCount % taskCount
        let verificationKeyModel = verificationKey.verificationKeyModel
        let packedPlaneCount = metalWindowedNonAdjacentFormComponentCount
            * metalWindowedNonAdjacentFormDigitCount

        return try await withThrowingTaskGroup(
            of: (Int, [UInt32], [Int8]).self
        ) { group in
            for taskIndex in 0..<taskCount {
                let startIndex = taskIndex * baseChunkCount + min(taskIndex, remainder)
                let endIndex = startIndex
                    + baseChunkCount
                    + (taskIndex < remainder ? 1 : 0)
                group.addTask {
                    let chunk = try makeMetalSchnorrVerificationBatchChunk(
                        signatures: signatures,
                        digests: digests,
                        verificationKeyModel: verificationKeyModel,
                        startIndex: startIndex,
                        endIndex: endIndex
                    )
                    return (
                        startIndex,
                        chunk.signatureXWords,
                        chunk.packedDigits
                    )
                }
            }

            var signatureXWords = Array(
                repeating: UInt32.zero,
                count: recordCount * 8
            )
            var packedDigits = Array(
                repeating: Int8.zero,
                count: recordCount * packedPlaneCount
            )
            for try await (startIndex, chunkSignatureXWords, chunkPackedDigits) in group {
                let chunkRecordCount = chunkSignatureXWords.count / 8
                precondition(chunkPackedDigits.count == chunkRecordCount * packedPlaneCount)

                let signatureDestinationStart = startIndex * 8
                for offset in chunkSignatureXWords.indices {
                    signatureXWords[signatureDestinationStart + offset]
                        = chunkSignatureXWords[offset]
                }
                for planeIndex in 0..<packedPlaneCount {
                    let sourceStart = planeIndex * chunkRecordCount
                    let destinationStart = planeIndex * recordCount + startIndex
                    for localRecordIndex in 0..<chunkRecordCount {
                        packedDigits[destinationStart + localRecordIndex]
                            = chunkPackedDigits[sourceStart + localRecordIndex]
                    }
                }
            }

            return MetalSchnorrVerificationBatchBenchmarkInput(
                recordCount: recordCount,
                signatureXWords: signatureXWords,
                windowedNonAdjacentFormDigits: packedDigits,
                windowedNonAdjacentFormTableWords: tableWords,
                expectedResults: expectedResults.map { $0 ? 1 : 0 }
            )
        }
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
        validateMetalSchnorrVaryingKeyInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            expectedResultCount: expectedResults.count,
            verificationKeyCount: verificationKeySource.count
        )
        let chunk = try makeMetalSchnorrVaryingKeyVerificationBatchChunk(
            signatures: signatures,
            digests: digests,
            verificationKeySource: verificationKeySource,
            startIndex: 0,
            endIndex: signatures.count
        )
        return MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput(
            recordCount: signatures.count,
            signatureXWords: chunk.signatureXWords,
            windowedNonAdjacentFormDigits: chunk.packedDigits,
            sharedGeneratorTableWords: MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput
                .cachedSharedGeneratorTableWords,
            varyingVerificationKeyTableWords: chunk.varyingVerificationKeyTableWords,
            expectedResults: expectedResults.map { $0 ? 1 : 0 }
        )
    }

    private static func makeMetalSchnorrVaryingKeyVerificationBatchInputParallel(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        expectedResults: [Bool],
        verificationKeySource: MetalSchnorrVerificationKeySource
    ) async throws -> MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput {
        validateMetalSchnorrVaryingKeyInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            expectedResultCount: expectedResults.count,
            verificationKeyCount: verificationKeySource.count
        )

        let recordCount = signatures.count
        guard recordCount > 0 else {
            return try makeMetalSchnorrVaryingKeyVerificationBatchInput(
                signatures: signatures,
                digests: digests,
                expectedResults: expectedResults,
                verificationKeySource: verificationKeySource
            )
        }

        let processorCount = max(1, ProcessInfo.processInfo.activeProcessorCount)
        let taskCount = min(
            processorCount,
            max(1, recordCount / minimumMetalSchnorrVerificationRecordsPerTask)
        )
        let baseChunkCount = recordCount / taskCount
        let remainder = recordCount % taskCount
        let packedPlaneCount = metalWindowedNonAdjacentFormComponentCount
            * metalWindowedNonAdjacentFormDigitCount
        let tableSlotCount = metalSchnorrVaryingVerificationKeyTableSlotCount

        return try await withThrowingTaskGroup(
            of: (Int, [UInt32], [Int8], [UInt32]).self
        ) { group in
            for taskIndex in 0..<taskCount {
                let startIndex = taskIndex * baseChunkCount + min(taskIndex, remainder)
                let endIndex = startIndex
                    + baseChunkCount
                    + (taskIndex < remainder ? 1 : 0)
                group.addTask {
                    let chunk = try makeMetalSchnorrVaryingKeyVerificationBatchChunk(
                        signatures: signatures,
                        digests: digests,
                        verificationKeySource: verificationKeySource,
                        startIndex: startIndex,
                        endIndex: endIndex
                    )
                    return (
                        startIndex,
                        chunk.signatureXWords,
                        chunk.packedDigits,
                        chunk.varyingVerificationKeyTableWords
                    )
                }
            }

            var signatureXWords = Array(
                repeating: UInt32.zero,
                count: recordCount * 8
            )
            var packedDigits = Array(
                repeating: Int8.zero,
                count: recordCount * packedPlaneCount
            )
            var varyingVerificationKeyTableWords = Array(
                repeating: UInt32.zero,
                count: recordCount * tableSlotCount
            )
            for try await (
                startIndex,
                chunkSignatureXWords,
                chunkPackedDigits,
                chunkTableWords
            ) in group {
                let chunkRecordCount = chunkSignatureXWords.count / 8
                precondition(chunkPackedDigits.count == chunkRecordCount * packedPlaneCount)
                precondition(chunkTableWords.count == chunkRecordCount * tableSlotCount)

                let signatureDestinationStart = startIndex * 8
                for offset in chunkSignatureXWords.indices {
                    signatureXWords[signatureDestinationStart + offset]
                        = chunkSignatureXWords[offset]
                }
                for planeIndex in 0..<packedPlaneCount {
                    let sourceStart = planeIndex * chunkRecordCount
                    let destinationStart = planeIndex * recordCount + startIndex
                    for localRecordIndex in 0..<chunkRecordCount {
                        packedDigits[destinationStart + localRecordIndex]
                            = chunkPackedDigits[sourceStart + localRecordIndex]
                    }
                }
                for slotIndex in 0..<tableSlotCount {
                    let sourceStart = slotIndex * chunkRecordCount
                    let destinationStart = slotIndex * recordCount + startIndex
                    for localRecordIndex in 0..<chunkRecordCount {
                        varyingVerificationKeyTableWords[destinationStart + localRecordIndex]
                            = chunkTableWords[sourceStart + localRecordIndex]
                    }
                }
            }

            return MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput(
                recordCount: recordCount,
                signatureXWords: signatureXWords,
                windowedNonAdjacentFormDigits: packedDigits,
                sharedGeneratorTableWords: MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput
                    .cachedSharedGeneratorTableWords,
                varyingVerificationKeyTableWords: varyingVerificationKeyTableWords,
                expectedResults: expectedResults.map { $0 ? 1 : 0 }
            )
        }
    }

    static func makeMetalSchnorrVerificationTableWords(
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) -> [UInt32] {
        windowedNonAdjacentFormTableWords(
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
        2 * metalWindowedNonAdjacentFormOddMultipleCount * 16
    }

    static var metalSchnorrVaryingVerificationKeyTableSlotCount: Int {
        2 * metalSchnorrVaryingVerificationKeyOddMultipleCount * 16
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

    private static func windowedNonAdjacentFormDigits(
        generatorScalar: ScalarModel,
        verificationKeyScalar: ScalarModel
    ) -> [Int8] {
        let generatorSplit = generatorScalar.splitForEndomorphism()
        let verificationKeySplit = verificationKeyScalar.splitForEndomorphism()
        var digits: [Int8] = .init()
        digits.reserveCapacity(4 * 130)
        appendWindowedNonAdjacentFormDigits(generatorSplit.firstScalar, to: &digits)
        appendWindowedNonAdjacentFormDigits(generatorSplit.secondScalar, to: &digits)
        appendWindowedNonAdjacentFormDigits(verificationKeySplit.firstScalar, to: &digits)
        appendWindowedNonAdjacentFormDigits(verificationKeySplit.secondScalar, to: &digits)
        return digits
    }

    private static var minimumMetalSchnorrVerificationRecordsPerTask: Int { 128 }

    private static func makeMetalSchnorrVerificationBatchChunk(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeyModel: VerificationKeyModel,
        startIndex: Int,
        endIndex: Int
    ) throws -> (signatureXWords: [UInt32], packedDigits: [Int8]) {
        let recordCount = endIndex - startIndex
        let packedPlaneCount = metalWindowedNonAdjacentFormComponentCount
            * metalWindowedNonAdjacentFormDigitCount
        var signatureXWords = Array(
            repeating: UInt32.zero,
            count: recordCount * 8
        )
        var packedDigits = Array(
            repeating: Int8.zero,
            count: recordCount * packedPlaneCount
        )

        for inputIndex in startIndex..<endIndex {
            let localRecordIndex = inputIndex - startIndex
            let signatureModel = signatures[inputIndex].signatureModel
            let signatureX = try FieldElementModel(data32: signatureModel.r)
            let signatureScalar = try ScalarModel(data32: signatureModel.s)
            let challenge = try ChallengeHashModel.makeChallengeScalar(
                digest32: digests[inputIndex].rawRepresentation,
                r: signatureX,
                verificationKeyModel: verificationKeyModel
            )
            writeLittleEndianWords(
                fromBigEndian32: signatureX.data32Bytes,
                to: &signatureXWords,
                startingAt: localRecordIndex * 8
            )

            let generatorSplit = signatureScalar.splitForEndomorphism()
            let verificationKeySplit = challenge.negateModN().splitForEndomorphism()
            writePackedWindowedNonAdjacentFormDigits(
                generatorSplit.firstScalar,
                component: 0,
                recordIndex: localRecordIndex,
                recordCount: recordCount,
                to: &packedDigits
            )
            writePackedWindowedNonAdjacentFormDigits(
                generatorSplit.secondScalar,
                component: 1,
                recordIndex: localRecordIndex,
                recordCount: recordCount,
                to: &packedDigits
            )
            writePackedWindowedNonAdjacentFormDigits(
                verificationKeySplit.firstScalar,
                component: 2,
                recordIndex: localRecordIndex,
                recordCount: recordCount,
                to: &packedDigits
            )
            writePackedWindowedNonAdjacentFormDigits(
                verificationKeySplit.secondScalar,
                component: 3,
                recordIndex: localRecordIndex,
                recordCount: recordCount,
                to: &packedDigits
            )
        }

        return (signatureXWords, packedDigits)
    }

    private static func validateMetalSchnorrVaryingKeyInputCounts(
        signatureCount: Int,
        digestCount: Int,
        expectedResultCount: Int,
        verificationKeyCount: Int
    ) {
        precondition(signatureCount == digestCount)
        precondition(signatureCount == expectedResultCount)
        precondition(signatureCount == verificationKeyCount)
    }

    private static func makeMetalSchnorrVaryingKeyVerificationBatchChunk(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeySource: MetalSchnorrVerificationKeySource,
        startIndex: Int,
        endIndex: Int
    ) throws -> (
        signatureXWords: [UInt32],
        packedDigits: [Int8],
        varyingVerificationKeyTableWords: [UInt32]
    ) {
        precondition(startIndex >= 0 && startIndex <= endIndex)
        precondition(endIndex <= signatures.count)
        let recordCount = endIndex - startIndex
        let packedPlaneCount = metalWindowedNonAdjacentFormComponentCount
            * metalWindowedNonAdjacentFormDigitCount
        var signatureXWords = Array(
            repeating: UInt32.zero,
            count: recordCount * 8
        )
        var packedDigits = Array(
            repeating: Int8.zero,
            count: recordCount * packedPlaneCount
        )
        var varyingVerificationKeyTableWords = Array(
            repeating: UInt32.zero,
            count: recordCount * metalSchnorrVaryingVerificationKeyTableSlotCount
        )
        var varyingVerificationKeyJacobianTable: [JacobianPointModel] = .init()
        varyingVerificationKeyJacobianTable.reserveCapacity(
            recordCount * metalSchnorrVaryingVerificationKeyOddMultipleCount
        )

        for inputIndex in startIndex..<endIndex {
            let localRecordIndex = inputIndex - startIndex
            let signatureModel = signatures[inputIndex].signatureModel
            let signatureX = try FieldElementModel(data32: signatureModel.r)
            let signatureScalar = try ScalarModel(data32: signatureModel.s)
            let parsedPublicKeyModel = try verificationKeySource.parsedPublicKeyModel(
                at: inputIndex
            )
            let challenge = try ChallengeHashModel.makeChallengeScalar(
                digest32: digests[inputIndex].rawRepresentation,
                r: signatureX,
                publicKey: parsedPublicKeyModel.affinePoint
            )
            writeLittleEndianWords(
                fromBigEndian32: signatureX.data32Bytes,
                to: &signatureXWords,
                startingAt: localRecordIndex * 8
            )

            let generatorSplit = signatureScalar.splitForEndomorphism()
            let verificationKeySplit = challenge.negateModN().splitForEndomorphism()
            writePackedWindowedNonAdjacentFormDigits(
                generatorSplit.firstScalar,
                component: 0,
                recordIndex: localRecordIndex,
                recordCount: recordCount,
                to: &packedDigits
            )
            writePackedWindowedNonAdjacentFormDigits(
                generatorSplit.secondScalar,
                component: 1,
                recordIndex: localRecordIndex,
                recordCount: recordCount,
                to: &packedDigits
            )
            writePackedWindowedNonAdjacentFormDigits(
                verificationKeySplit.firstScalar,
                width: metalSchnorrVaryingVerificationKeyWindowedNonAdjacentFormWidth,
                component: 2,
                recordIndex: localRecordIndex,
                recordCount: recordCount,
                to: &packedDigits
            )
            writePackedWindowedNonAdjacentFormDigits(
                verificationKeySplit.secondScalar,
                width: metalSchnorrVaryingVerificationKeyWindowedNonAdjacentFormWidth,
                component: 3,
                recordIndex: localRecordIndex,
                recordCount: recordCount,
                to: &packedDigits
            )
            appendMetalOddMultiplesJacobianTable(
                for: parsedPublicKeyModel.affinePoint,
                oddMultipleCount: metalSchnorrVaryingVerificationKeyOddMultipleCount,
                to: &varyingVerificationKeyJacobianTable
            )
        }

        let varyingVerificationKeyAffineTable = JacobianPointModel
            .convertNonInfinityBatchToAffine(varyingVerificationKeyJacobianTable)
        precondition(
            varyingVerificationKeyAffineTable.count
                == recordCount * metalSchnorrVaryingVerificationKeyOddMultipleCount
        )
        for localRecordIndex in 0..<recordCount {
            let tableStartIndex = localRecordIndex
                * metalSchnorrVaryingVerificationKeyOddMultipleCount
            writeMetalSchnorrVaryingVerificationKeyTable(
                varyingVerificationKeyAffineTable,
                tableStartIndex: tableStartIndex,
                applyingEndomorphism: false,
                startingSlotIndex: 0,
                recordIndex: localRecordIndex,
                recordCount: recordCount,
                to: &varyingVerificationKeyTableWords
            )
            writeMetalSchnorrVaryingVerificationKeyTable(
                varyingVerificationKeyAffineTable,
                tableStartIndex: tableStartIndex,
                applyingEndomorphism: true,
                startingSlotIndex:
                    metalSchnorrVaryingVerificationKeyOddMultipleCount * 16,
                recordIndex: localRecordIndex,
                recordCount: recordCount,
                to: &varyingVerificationKeyTableWords
            )
        }

        return (signatureXWords, packedDigits, varyingVerificationKeyTableWords)
    }

    private static func writePackedWindowedNonAdjacentFormDigits(
        _ scalar: SignedScalar128Model,
        width: Int = metalWindowedNonAdjacentFormWidth,
        component: Int,
        recordIndex: Int,
        recordCount: Int,
        to packedDigits: inout [Int8]
    ) {
        let digits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            scalar,
            width: width
        )
        for digitIndex in 0..<digits.count {
            let destinationIndex = (
                component * metalWindowedNonAdjacentFormDigitCount + digitIndex
            ) * recordCount + recordIndex
            packedDigits[destinationIndex] = digits[digitIndex]
        }
    }

    private static func writeLittleEndianWords(
        fromBigEndian32 data: Data,
        to words: inout [UInt32],
        startingAt destinationStart: Int
    ) {
        precondition(data.count == 32, "Expected exactly 32 bytes.")
        var destinationIndex = destinationStart
        for offset in stride(from: 28, through: 0, by: -4) {
            words[destinationIndex] = UInt32(data[offset]) << 24
                | UInt32(data[offset + 1]) << 16
                | UInt32(data[offset + 2]) << 8
                | UInt32(data[offset + 3])
            destinationIndex += 1
        }
    }

    private static func appendWindowedNonAdjacentFormDigits(
        _ signedScalar: SignedScalar128Model,
        to digits: inout [Int8]
    ) {
        let wnaf = SignedScalar128Model.makeWindowedNonAdjacentForm(
            signedScalar,
            width: metalWindowedNonAdjacentFormWidth
        )
        for digit in wnaf.values {
            digits.append(digit)
        }
        if wnaf.count < 130 {
            digits.append(contentsOf: Array(repeating: Int8.zero, count: 130 - wnaf.count))
        }
    }

    static func makeMetalSchnorrSharedGeneratorTableWords() -> [UInt32] {
        let generatorTable = makeMetalOddMultiplesAffineTable(
            for: ScalarMultiplicationModel.generator
        )
        var words: [UInt32] = .init()
        words.reserveCapacity(metalSchnorrSharedGeneratorTableWordCount)
        appendTableWords(generatorTable, to: &words)
        appendTableWords(generatorTable, applyingEndomorphism: true, to: &words)
        return words
    }

    private static func writeMetalSchnorrVaryingVerificationKeyTable(
        _ table: [AffinePointModel],
        tableStartIndex: Int,
        applyingEndomorphism: Bool,
        startingSlotIndex: Int,
        recordIndex: Int,
        recordCount: Int,
        to words: inout [UInt32]
    ) {
        for pointIndex in 0..<metalSchnorrVaryingVerificationKeyOddMultipleCount {
            let sourcePoint = table[tableStartIndex + pointIndex]
            let affinePoint = applyingEndomorphism
                ? sourcePoint.applyEndomorphism()
                : sourcePoint
            let pointSlotIndex = startingSlotIndex + pointIndex * 16
            writeSlotMajorLittleEndianWords(
                fromBigEndian32: affinePoint.x.data32Bytes,
                startingSlotIndex: pointSlotIndex,
                recordIndex: recordIndex,
                recordCount: recordCount,
                to: &words
            )
            writeSlotMajorLittleEndianWords(
                fromBigEndian32: affinePoint.y.data32Bytes,
                startingSlotIndex: pointSlotIndex + 8,
                recordIndex: recordIndex,
                recordCount: recordCount,
                to: &words
            )
        }
    }

    private static func writeSlotMajorLittleEndianWords(
        fromBigEndian32 data: Data,
        startingSlotIndex: Int,
        recordIndex: Int,
        recordCount: Int,
        to words: inout [UInt32]
    ) {
        precondition(data.count == 32, "Expected exactly 32 bytes.")
        var slotIndex = startingSlotIndex
        for offset in stride(from: 28, through: 0, by: -4) {
            let destinationIndex = metalSchnorrVaryingVerificationKeyTableWordOffset(
                recordIndex: recordIndex,
                slotIndex: slotIndex,
                recordCount: recordCount
            )
            words[destinationIndex] = UInt32(data[offset]) << 24
                | UInt32(data[offset + 1]) << 16
                | UInt32(data[offset + 2]) << 8
                | UInt32(data[offset + 3])
            slotIndex += 1
        }
    }

    private static func windowedNonAdjacentFormTableWords(
        verificationKeyModel: VerificationKeyModel
    ) -> [UInt32] {
        var words: [UInt32] = .init()
        words.reserveCapacity(4 * metalWindowedNonAdjacentFormOddMultipleCount * 16)
        appendTableWords(
            makeMetalOddMultiplesAffineTable(for: ScalarMultiplicationModel.generator),
            to: &words
        )
        appendTableWords(
            makeMetalOddMultiplesAffineTable(for: ScalarMultiplicationModel.generator.applyEndomorphism()),
            to: &words
        )
        appendTableWords(
            makeMetalOddMultiplesAffineTable(for: verificationKeyModel.affinePoint),
            to: &words
        )
        appendTableWords(
            makeMetalOddMultiplesAffineTable(for: verificationKeyModel.affinePoint.applyEndomorphism()),
            to: &words
        )
        return words
    }

    private static func makeMetalOddMultiplesAffineTable(
        for basePoint: AffinePointModel
    ) -> [AffinePointModel] {
        var jacobianPoints: [JacobianPointModel] = .init()
        jacobianPoints.reserveCapacity(metalWindowedNonAdjacentFormOddMultipleCount)

        appendMetalOddMultiplesJacobianTable(for: basePoint, to: &jacobianPoints)
        return JacobianPointModel.convertNonInfinityBatchToAffine(jacobianPoints)
    }

    private static func appendMetalOddMultiplesJacobianTable(
        for basePoint: AffinePointModel,
        oddMultipleCount: Int = metalWindowedNonAdjacentFormOddMultipleCount,
        to jacobianPoints: inout [JacobianPointModel]
    ) {
        let baseJacobian = JacobianPointModel(affine: basePoint)
        let doubleBase = baseJacobian.double()
        var accumulator = baseJacobian
        for _ in 0..<oddMultipleCount {
            jacobianPoints.append(accumulator)
            accumulator = accumulator.add(doubleBase)
        }
    }

    private static func appendTableWords(
        _ table: [AffinePointModel],
        applyingEndomorphism: Bool = false,
        to words: inout [UInt32]
    ) {
        for sourcePoint in table {
            let affinePoint = applyingEndomorphism
                ? sourcePoint.applyEndomorphism()
                : sourcePoint
            words.append(contentsOf: littleEndianWords(fromBigEndian32: affinePoint.x.data32Bytes))
            words.append(contentsOf: littleEndianWords(fromBigEndian32: affinePoint.y.data32Bytes))
        }
    }

    private static func littleEndianWords(fromBigEndian32 data: Data) -> [UInt32] {
        precondition(data.count == 32, "Expected exactly 32 bytes.")
        var words: [UInt32] = .init()
        words.reserveCapacity(8)
        for offset in stride(from: 28, through: 0, by: -4) {
            let word = UInt32(data[offset]) << 24
                | UInt32(data[offset + 1]) << 16
                | UInt32(data[offset + 2]) << 8
                | UInt32(data[offset + 3])
            words.append(word)
        }
        return words
    }
}
