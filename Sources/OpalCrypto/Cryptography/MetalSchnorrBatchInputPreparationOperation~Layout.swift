// MetalSchnorrBatchInputPreparationOperation~Layout.swift

import Foundation

extension MetalSchnorrBatchInputPreparationOperation {
    static func mergePreparedRecords(
        localStart: Int,
        recordCount: Int,
        chunkWords: [UInt32],
        chunkDigits: [Int8],
        signatureXWords: inout [UInt32],
        packedDigits: inout [Int8]
    ) {
        let chunkCount = chunkWords.count / 8
        precondition(chunkDigits.count == chunkCount * packedPlaneCount)
        let wordDestinationStart = localStart * 8
        for sourceIndex in chunkWords.indices {
            signatureXWords[wordDestinationStart + sourceIndex] = chunkWords[sourceIndex]
        }
        for planeIndex in 0..<packedPlaneCount {
            let sourceStart = planeIndex * chunkCount
            let destinationStart = planeIndex * recordCount + localStart
            for chunkIndex in 0..<chunkCount {
                packedDigits[destinationStart + chunkIndex]
                    = chunkDigits[sourceStart + chunkIndex]
            }
        }
    }

    static func writeScalarDigits(
        generatorScalar: ScalarModel,
        verificationKeyScalar: ScalarModel,
        recordIndex: Int,
        recordCount: Int,
        varyingKey: Bool,
        to packedDigits: inout [Int8]
    ) {
        let generatorSplit = generatorScalar.splitForEndomorphism()
        let verificationKeySplit = verificationKeyScalar.splitForEndomorphism()
        writeWindowedNonAdjacentFormDigits(
            generatorSplit.firstScalar,
            width: 7,
            component: 0,
            recordIndex: recordIndex,
            recordCount: recordCount,
            to: &packedDigits
        )
        writeWindowedNonAdjacentFormDigits(
            generatorSplit.secondScalar,
            width: 7,
            component: 1,
            recordIndex: recordIndex,
            recordCount: recordCount,
            to: &packedDigits
        )
        let verificationKeyWidth = varyingKey ? 3 : 7
        writeWindowedNonAdjacentFormDigits(
            verificationKeySplit.firstScalar,
            width: verificationKeyWidth,
            component: 2,
            recordIndex: recordIndex,
            recordCount: recordCount,
            to: &packedDigits
        )
        writeWindowedNonAdjacentFormDigits(
            verificationKeySplit.secondScalar,
            width: verificationKeyWidth,
            component: 3,
            recordIndex: recordIndex,
            recordCount: recordCount,
            to: &packedDigits
        )
    }

    static func writeWindowedNonAdjacentFormDigits(
        _ scalar: SignedScalar128Model,
        width: Int,
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
            let destination = (component * packedDigitCount + digitIndex)
                * recordCount
                + recordIndex
            packedDigits[destination] = digits[digitIndex]
        }
    }

    static func writeLittleEndianWords(
        fromBigEndian32 data: Data,
        to words: inout [UInt32],
        startingAt destinationStart: Int
    ) {
        precondition(data.count == 32)
        var destination = destinationStart
        for offset in stride(from: 28, through: 0, by: -4) {
            words[destination] = UInt32(data[offset]) << 24
                | UInt32(data[offset + 1]) << 16
                | UInt32(data[offset + 2]) << 8
                | UInt32(data[offset + 3])
            destination += 1
        }
    }
}
