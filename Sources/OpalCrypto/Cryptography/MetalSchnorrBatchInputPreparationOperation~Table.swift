// MetalSchnorrBatchInputPreparationOperation~Table.swift

import Foundation

extension MetalSchnorrBatchInputPreparationOperation {
    static func makeCachedKeyTableWords(
        verificationKeyModel: VerificationKeyModel
    ) -> [UInt32] {
        var words = sharedGeneratorTableWords
        words.reserveCapacity(cachedTableWordCount)
        appendTableWords(makeOddMultiplesAffineTable(for: verificationKeyModel.affinePoint), to: &words)
        appendTableWords(
            makeOddMultiplesAffineTable(
                for: verificationKeyModel.affinePoint.applyEndomorphism()
            ),
            to: &words
        )
        return words
    }

    static func makeSharedGeneratorTableWords() -> [UInt32] {
        let table = makeOddMultiplesAffineTable(for: ScalarMultiplicationModel.generator)
        var words: [UInt32] = []
        words.reserveCapacity(sharedGeneratorTableWordCount)
        appendTableWords(table, to: &words)
        appendTableWords(table, applyingEndomorphism: true, to: &words)
        return words
    }

    static func makeOddMultiplesAffineTable(
        for basePoint: AffinePointModel
    ) -> [AffinePointModel] {
        var jacobianPoints: [JacobianPointModel] = []
        jacobianPoints.reserveCapacity(cachedOddMultipleCount)
        appendOddMultiplesJacobianTable(
            for: basePoint,
            count: cachedOddMultipleCount,
            to: &jacobianPoints
        )
        return JacobianPointModel.convertNonInfinityBatchToAffine(jacobianPoints)
    }

    static func appendOddMultiplesJacobianTable(
        for basePoint: AffinePointModel,
        count: Int,
        to points: inout [JacobianPointModel]
    ) {
        let base = JacobianPointModel(affine: basePoint)
        let doubledBase = base.double()
        var accumulator = base
        for _ in 0..<count {
            points.append(accumulator)
            accumulator = accumulator.add(doubledBase)
        }
    }

    static func appendTableWords(
        _ table: [AffinePointModel],
        applyingEndomorphism: Bool = false,
        to words: inout [UInt32]
    ) {
        for sourcePoint in table {
            let point = applyingEndomorphism
                ? sourcePoint.applyEndomorphism()
                : sourcePoint
            appendLittleEndianWords(fromBigEndian32: point.x.data32Bytes, to: &words)
            appendLittleEndianWords(fromBigEndian32: point.y.data32Bytes, to: &words)
        }
    }

    static func appendLittleEndianWords(
        fromBigEndian32 data: Data,
        to words: inout [UInt32]
    ) {
        precondition(data.count == 32)
        for offset in stride(from: 28, through: 0, by: -4) {
            words.append(
                UInt32(data[offset]) << 24
                    | UInt32(data[offset + 1]) << 16
                    | UInt32(data[offset + 2]) << 8
                    | UInt32(data[offset + 3])
            )
        }
    }

    static func writeVaryingKeyTable(
        _ table: [AffinePointModel],
        tableStart: Int,
        applyingEndomorphism: Bool,
        startingSlot: Int,
        recordIndex: Int,
        recordCount: Int,
        to words: inout [UInt32]
    ) {
        for pointIndex in 0..<varyingKeyOddMultipleCount {
            let sourcePoint = table[tableStart + pointIndex]
            let point = applyingEndomorphism
                ? sourcePoint.applyEndomorphism()
                : sourcePoint
            let pointSlot = startingSlot + pointIndex * 16
            writeSlotMajorLittleEndianWords(
                fromBigEndian32: point.x.data32Bytes,
                startingSlot: pointSlot,
                recordIndex: recordIndex,
                recordCount: recordCount,
                to: &words
            )
            writeSlotMajorLittleEndianWords(
                fromBigEndian32: point.y.data32Bytes,
                startingSlot: pointSlot + 8,
                recordIndex: recordIndex,
                recordCount: recordCount,
                to: &words
            )
        }
    }

    static func writeSlotMajorLittleEndianWords(
        fromBigEndian32 data: Data,
        startingSlot: Int,
        recordIndex: Int,
        recordCount: Int,
        to words: inout [UInt32]
    ) {
        precondition(data.count == 32)
        var slot = startingSlot
        for offset in stride(from: 28, through: 0, by: -4) {
            words[slot * recordCount + recordIndex] = UInt32(data[offset]) << 24
                | UInt32(data[offset + 1]) << 16
                | UInt32(data[offset + 2]) << 8
                | UInt32(data[offset + 3])
            slot += 1
        }
    }
}
