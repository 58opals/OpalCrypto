// MetalVerificationBenchmarkSupport.swift

import Foundation

package struct MetalSchnorrVerificationBenchmarkInput: Sendable {
    package let signatureXWords: [UInt32]
    package let windowedNonAdjacentFormDigits: [Int32]
    package let windowedNonAdjacentFormTableWords: [UInt32]
    package let expected: Bool

    package init(
        signatureXWords: [UInt32],
        windowedNonAdjacentFormDigits: [Int32],
        windowedNonAdjacentFormTableWords: [UInt32],
        expected: Bool
    ) {
        self.signatureXWords = signatureXWords
        self.windowedNonAdjacentFormDigits = windowedNonAdjacentFormDigits
        self.windowedNonAdjacentFormTableWords = windowedNonAdjacentFormTableWords
        self.expected = expected
    }
}

package struct MetalSchnorrVerificationBatchBenchmarkInput: Sendable {
    package let recordCount: Int
    package let signatureXWords: [UInt32]
    package let windowedNonAdjacentFormDigits: [Int32]
    package let windowedNonAdjacentFormTableWords: [UInt32]
    package let expectedResults: [UInt32]

    package init(
        recordCount: Int,
        signatureXWords: [UInt32],
        windowedNonAdjacentFormDigits: [Int32],
        windowedNonAdjacentFormTableWords: [UInt32],
        expectedResults: [UInt32]
    ) {
        self.recordCount = recordCount
        self.signatureXWords = signatureXWords
        self.windowedNonAdjacentFormDigits = windowedNonAdjacentFormDigits
        self.windowedNonAdjacentFormTableWords = windowedNonAdjacentFormTableWords
        self.expectedResults = expectedResults
    }

    package var checksum: Int {
        var checksum = recordCount
        for (index, expectedResult) in expectedResults.enumerated() {
            checksum ^= expectedResult == 1 ? index + 1 : -(index + 1)
        }
        checksum ^= signatureXWords.count
        checksum ^= windowedNonAdjacentFormDigits.count
        checksum ^= windowedNonAdjacentFormTableWords.count
        return checksum
    }
}

package extension PerformanceBenchmarkOperations {
    private static var metalWindowedNonAdjacentFormWidth: Int { 7 }
    private static var metalWindowedNonAdjacentFormOddMultipleCount: Int { 32 }

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
            windowedNonAdjacentFormDigits: Self.windowedNonAdjacentFormDigits(
                generatorScalar: signatureScalar,
                verificationKeyScalar: negatedChallenge
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
        var digitWords: [Int32] = .init()
        digitWords.reserveCapacity(signatures.count * 4 * 130)

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
            digitWords.append(
                contentsOf: Self.windowedNonAdjacentFormDigits(
                    generatorScalar: signatureScalar,
                    verificationKeyScalar: challenge.negateModN()
                )
            )
        }

        return MetalSchnorrVerificationBatchBenchmarkInput(
            recordCount: signatures.count,
            signatureXWords: signatureXWords,
            windowedNonAdjacentFormDigits: digitWords,
            windowedNonAdjacentFormTableWords: tableWords,
            expectedResults: expectedResults.map { $0 ? 1 : 0 }
        )
    }

    static func makeMetalSchnorrVerificationTableWords(
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) -> [UInt32] {
        windowedNonAdjacentFormTableWords(
            verificationKeyModel: verificationKey.verificationKeyModel
        )
    }

    private static func windowedNonAdjacentFormDigits(
        generatorScalar: ScalarModel,
        verificationKeyScalar: ScalarModel
    ) -> [Int32] {
        let generatorSplit = generatorScalar.splitForEndomorphism()
        let verificationKeySplit = verificationKeyScalar.splitForEndomorphism()
        var digits: [Int32] = .init()
        digits.reserveCapacity(4 * 130)
        appendWindowedNonAdjacentFormDigits(generatorSplit.firstScalar, to: &digits)
        appendWindowedNonAdjacentFormDigits(generatorSplit.secondScalar, to: &digits)
        appendWindowedNonAdjacentFormDigits(verificationKeySplit.firstScalar, to: &digits)
        appendWindowedNonAdjacentFormDigits(verificationKeySplit.secondScalar, to: &digits)
        return digits
    }

    private static func appendWindowedNonAdjacentFormDigits(
        _ signedScalar: SignedScalar128Model,
        to digits: inout [Int32]
    ) {
        let wnaf = SignedScalar128Model.makeWindowedNonAdjacentForm(
            signedScalar,
            width: metalWindowedNonAdjacentFormWidth
        )
        for digit in wnaf.values {
            digits.append(Int32(digit))
        }
        if wnaf.count < 130 {
            digits.append(contentsOf: Array(repeating: Int32.zero, count: 130 - wnaf.count))
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

        let baseJacobian = JacobianPointModel(affine: basePoint)
        let doubleBase = baseJacobian.double()
        var accumulator = baseJacobian
        for _ in 0..<metalWindowedNonAdjacentFormOddMultipleCount {
            jacobianPoints.append(accumulator)
            accumulator = accumulator.add(doubleBase)
        }

        return JacobianPointModel.convertNonInfinityBatchToAffine(jacobianPoints)
    }

    private static func appendTableWords(
        _ table: [AffinePointModel],
        to words: inout [UInt32]
    ) {
        for affinePoint in table {
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
