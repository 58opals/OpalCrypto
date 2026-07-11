// MetalSchnorrBatchInputPreparationOperation~CachedKey.swift

import Foundation

extension MetalSchnorrBatchInputPreparationOperation {
    static func prepareCachedKeyInput(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        range: Range<Int>,
        context: MetalSchnorrCachedKeyContext
    ) async throws -> MetalSchnorrCachedKeyBatchInput {
        try validateRange(
            range,
            signatureCount: signatures.count,
            digestCount: digests.count
        )
        try Task.checkCancellation()
        guard !range.isEmpty else {
            return try MetalSchnorrCachedKeyBatchInput(
                recordCount: 0,
                signatureXWords: [],
                packedDigits: [],
                tableIdentifier: context.tableIdentifier,
                tableWords: context.tableWords
            )
        }

        let localRanges = taskRanges(recordCount: range.count)
        let preparedRecords = try await withThrowingTaskGroup(
            of: (Int, [UInt32], [Int8]).self
        ) { group in
            for localRange in localRanges {
                group.addTask {
                    try Task.checkCancellation()
                    let prepared = try prepareCachedKeyRecords(
                        signatures: signatures,
                        digests: digests,
                        inputOffset: range.lowerBound,
                        localRange: localRange,
                        verificationKeyModel: context.verificationKeyModel
                    )
                    return (
                        localRange.lowerBound,
                        prepared.signatureXWords,
                        prepared.packedDigits
                    )
                }
            }

            var signatureXWords = Array(
                repeating: UInt32.zero,
                count: range.count * 8
            )
            var packedDigits = Array(
                repeating: Int8.zero,
                count: range.count * packedPlaneCount
            )
            for try await (localStart, chunkWords, chunkDigits) in group {
                mergePreparedRecords(
                    localStart: localStart,
                    recordCount: range.count,
                    chunkWords: chunkWords,
                    chunkDigits: chunkDigits,
                    signatureXWords: &signatureXWords,
                    packedDigits: &packedDigits
                )
            }
            return (signatureXWords, packedDigits)
        }

        return try MetalSchnorrCachedKeyBatchInput(
            recordCount: range.count,
            signatureXWords: preparedRecords.0,
            packedDigits: preparedRecords.1,
            tableIdentifier: context.tableIdentifier,
            tableWords: context.tableWords
        )
    }

    static func prepareCachedKeyRecords(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        inputOffset: Int,
        localRange: Range<Int>,
        verificationKeyModel: VerificationKeyModel
    ) throws -> (signatureXWords: [UInt32], packedDigits: [Int8]) {
        let recordCount = localRange.count
        var signatureXWords = Array(repeating: UInt32.zero, count: recordCount * 8)
        var packedDigits = Array(repeating: Int8.zero, count: recordCount * packedPlaneCount)

        for localIndex in localRange {
            if localIndex.isMultiple(of: 128) {
                try Task.checkCancellation()
            }
            let inputIndex = inputOffset + localIndex
            let outputIndex = localIndex - localRange.lowerBound
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
                startingAt: outputIndex * 8
            )
            writeScalarDigits(
                generatorScalar: signatureScalar,
                verificationKeyScalar: challenge.negateModN(),
                recordIndex: outputIndex,
                recordCount: recordCount,
                varyingKey: false,
                to: &packedDigits
            )
        }
        return (signatureXWords, packedDigits)
    }
}
