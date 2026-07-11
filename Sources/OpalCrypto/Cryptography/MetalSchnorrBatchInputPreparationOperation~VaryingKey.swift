// MetalSchnorrBatchInputPreparationOperation~VaryingKey.swift

import Foundation

extension MetalSchnorrBatchInputPreparationOperation {
    static func prepareVaryingKeyInput(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        publicKeys: [OpalCrypto.Secp256k1.PublicKey],
        range: Range<Int>
    ) async throws -> MetalSchnorrVaryingKeyBatchInput {
        try validateRange(
            range,
            signatureCount: signatures.count,
            digestCount: digests.count,
            publicKeyCount: publicKeys.count
        )
        try Task.checkCancellation()
        guard !range.isEmpty else {
            return try MetalSchnorrVaryingKeyBatchInput(
                recordCount: 0,
                signatureXWords: [],
                packedDigits: [],
                sharedGeneratorTableWords: sharedGeneratorTableWords,
                varyingVerificationKeyTableWords: []
            )
        }

        let localRanges = taskRanges(recordCount: range.count)
        let preparedRecords = try await withThrowingTaskGroup(
            of: (Int, [UInt32], [Int8], [UInt32]).self
        ) { group in
            for localRange in localRanges {
                group.addTask {
                    try Task.checkCancellation()
                    let prepared = try prepareVaryingKeyRecords(
                        signatures: signatures,
                        digests: digests,
                        publicKeys: publicKeys,
                        inputOffset: range.lowerBound,
                        localRange: localRange
                    )
                    return (
                        localRange.lowerBound,
                        prepared.signatureXWords,
                        prepared.packedDigits,
                        prepared.tableWords
                    )
                }
            }

            var signatureXWords = Array(repeating: UInt32.zero, count: range.count * 8)
            var packedDigits = Array(repeating: Int8.zero, count: range.count * packedPlaneCount)
            var tableWords = Array(
                repeating: UInt32.zero,
                count: range.count * varyingKeyTableSlotCount
            )
            for try await (localStart, chunkWords, chunkDigits, chunkTableWords) in group {
                let chunkCount = chunkWords.count / 8
                mergePreparedRecords(
                    localStart: localStart,
                    recordCount: range.count,
                    chunkWords: chunkWords,
                    chunkDigits: chunkDigits,
                    signatureXWords: &signatureXWords,
                    packedDigits: &packedDigits
                )
                for slotIndex in 0..<varyingKeyTableSlotCount {
                    let sourceStart = slotIndex * chunkCount
                    let destinationStart = slotIndex * range.count + localStart
                    for chunkIndex in 0..<chunkCount {
                        tableWords[destinationStart + chunkIndex]
                            = chunkTableWords[sourceStart + chunkIndex]
                    }
                }
            }
            return (signatureXWords, packedDigits, tableWords)
        }

        return try MetalSchnorrVaryingKeyBatchInput(
            recordCount: range.count,
            signatureXWords: preparedRecords.0,
            packedDigits: preparedRecords.1,
            sharedGeneratorTableWords: sharedGeneratorTableWords,
            varyingVerificationKeyTableWords: preparedRecords.2
        )
    }

    static func prepareVaryingKeyRecords(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        publicKeys: [OpalCrypto.Secp256k1.PublicKey],
        inputOffset: Int,
        localRange: Range<Int>
    ) throws -> (signatureXWords: [UInt32], packedDigits: [Int8], tableWords: [UInt32]) {
        let recordCount = localRange.count
        var signatureXWords = Array(repeating: UInt32.zero, count: recordCount * 8)
        var packedDigits = Array(repeating: Int8.zero, count: recordCount * packedPlaneCount)
        var jacobianPoints: [JacobianPointModel] = []
        jacobianPoints.reserveCapacity(recordCount * varyingKeyOddMultipleCount)

        for localIndex in localRange {
            if localIndex.isMultiple(of: 128) {
                try Task.checkCancellation()
            }
            let inputIndex = inputOffset + localIndex
            let outputIndex = localIndex - localRange.lowerBound
            let signatureModel = signatures[inputIndex].signatureModel
            let signatureX = try FieldElementModel(data32: signatureModel.r)
            let signatureScalar = try ScalarModel(data32: signatureModel.s)
            let publicKey = publicKeys[inputIndex].parsedPublicKeyModel
            let challenge = try ChallengeHashModel.makeChallengeScalar(
                digest32: digests[inputIndex].rawRepresentation,
                r: signatureX,
                publicKey: publicKey.affinePoint
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
                varyingKey: true,
                to: &packedDigits
            )
            appendOddMultiplesJacobianTable(
                for: publicKey.affinePoint,
                count: varyingKeyOddMultipleCount,
                to: &jacobianPoints
            )
        }

        let affinePoints = JacobianPointModel.convertNonInfinityBatchToAffine(jacobianPoints)
        guard affinePoints.count == recordCount * varyingKeyOddMultipleCount else {
            throw MetalSchnorrBatchVerificationError.invalidInput
        }
        var tableWords = Array(
            repeating: UInt32.zero,
            count: recordCount * varyingKeyTableSlotCount
        )
        for recordIndex in 0..<recordCount {
            let tableStart = recordIndex * varyingKeyOddMultipleCount
            writeVaryingKeyTable(
                affinePoints,
                tableStart: tableStart,
                applyingEndomorphism: false,
                startingSlot: 0,
                recordIndex: recordIndex,
                recordCount: recordCount,
                to: &tableWords
            )
            writeVaryingKeyTable(
                affinePoints,
                tableStart: tableStart,
                applyingEndomorphism: true,
                startingSlot: varyingKeyOddMultipleCount * 16,
                recordIndex: recordIndex,
                recordCount: recordCount,
                to: &tableWords
            )
        }
        return (signatureXWords, packedDigits, tableWords)
    }
}
