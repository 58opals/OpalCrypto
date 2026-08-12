// OpalCryptoBenchmarks+MetalSchnorrVerificationCore.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    enum MetalSchnorrVerificationCore {
        private static let stageMeasurementRecorder = StageMeasurementRecorder()

        static func resetStageMeasurements() {
            stageMeasurementRecorder.reset()
        }

        static func takeStageMeasurements() -> [StageMeasurement] {
            stageMeasurementRecorder.take()
        }

        static func recordStageMeasurement(_ measurement: StageMeasurement) {
            stageMeasurementRecorder.append(measurement)
        }

        static func configuration() throws -> Configuration {
            #if canImport(Metal) && canImport(OpalCryptoMetal)
            try MetalSchnorrVerificationRuntime.instance().configuration
            #else
            throw MetalVerificationProbeError.unavailable
            #endif
        }

        static func run(
            input: MetalSchnorrVerificationBenchmarkInput,
            count: Int,
            threadgroupWidth: Int? = nil
        ) throws -> Int {
            #if canImport(Metal) && canImport(OpalCryptoMetal)
            let preparationStart = DispatchTime.now().uptimeNanoseconds
            let recordWords = makeRecordWords(input: input, count: count)
            let packedDigits = makePackedDigits(input: input, count: count)
            let preparationNanoseconds = DispatchTime.now().uptimeNanoseconds
                - preparationStart
            return try MetalSchnorrVerificationRuntime.instance().run(
                recordWords: recordWords,
                packedDigits: packedDigits,
                tableWords: input.windowedNonAdjacentFormTableWords,
                expectedResults: Array(repeating: input.expected ? 1 : 0, count: count),
                recordCount: count,
                requestedThreadgroupWidth: threadgroupWidth,
                cpuPreparationNanoseconds: preparationNanoseconds
            )
            #else
            throw MetalVerificationProbeError.unavailable
            #endif
        }

        static func run(
            batchInput: MetalSchnorrVerificationBatchBenchmarkInput,
            threadgroupWidth: Int? = nil,
            cpuPreparationNanoseconds: UInt64 = 0
        ) throws -> Int {
            #if canImport(Metal) && canImport(OpalCryptoMetal)
            try MetalSchnorrVerificationRuntime.instance().run(
                recordWords: batchInput.signatureXWords,
                packedDigits: batchInput.windowedNonAdjacentFormDigits,
                tableWords: batchInput.windowedNonAdjacentFormTableWords,
                expectedResults: batchInput.expectedResults,
                recordCount: batchInput.recordCount,
                requestedThreadgroupWidth: threadgroupWidth,
                cpuPreparationNanoseconds: cpuPreparationNanoseconds
            )
            #else
            throw MetalVerificationProbeError.unavailable
            #endif
        }

        static func run(
            varyingKeyBatchInput: MetalSchnorrVaryingKeyVerificationBatchBenchmarkInput,
            threadgroupWidth: Int? = nil,
            cpuPreparationNanoseconds: UInt64 = 0
        ) throws -> Int {
            #if canImport(Metal) && canImport(OpalCryptoMetal)
            try MetalSchnorrVerificationRuntime.instance().run(
                varyingKeyRecordWords: varyingKeyBatchInput.signatureXWords,
                packedDigits: varyingKeyBatchInput.windowedNonAdjacentFormDigits,
                sharedGeneratorTableWords: varyingKeyBatchInput.sharedGeneratorTableWords,
                varyingVerificationKeyTableWords:
                    varyingKeyBatchInput.varyingVerificationKeyTableWords,
                expectedResults: varyingKeyBatchInput.expectedResults,
                recordCount: varyingKeyBatchInput.recordCount,
                tableCacheIdentifier: varyingKeyBatchInput.tableCacheIdentifier,
                requestedThreadgroupWidth: threadgroupWidth,
                cpuPreparationNanoseconds: cpuPreparationNanoseconds
            )
            #else
            throw MetalVerificationProbeError.unavailable
            #endif
        }

        static func validateFieldOperations(
            _ cases: [MetalFieldValidationBenchmarkCase]
        ) throws -> Int {
            #if canImport(Metal) && canImport(OpalCryptoMetal)
            try MetalSchnorrVerificationRuntime.instance().validateFieldOperations(cases)
            #else
            throw MetalVerificationProbeError.unavailable
            #endif
        }

        private static func makeRecordWords(
            input: MetalSchnorrVerificationBenchmarkInput,
            count: Int
        ) -> [UInt32] {
            var words: [UInt32] = .init()
            words.reserveCapacity(count * 8)
            for _ in 0..<count {
                words.append(contentsOf: input.signatureXWords)
            }
            return words
        }

        private static func makePackedDigits(
            input: MetalSchnorrVerificationBenchmarkInput,
            count: Int
        ) -> [Int8] {
            let componentCount = PerformanceBenchmarkOperations
                .metalWindowedNonAdjacentFormComponentCount
            let digitCount = PerformanceBenchmarkOperations
                .metalWindowedNonAdjacentFormDigitCount
            precondition(input.windowedNonAdjacentFormDigits.count == componentCount * digitCount)

            var packedDigits = Array(
                repeating: Int8.zero,
                count: count * componentCount * digitCount
            )
            for component in 0..<componentCount {
                for digitIndex in 0..<digitCount {
                    let digit = input.windowedNonAdjacentFormDigits[
                        component * digitCount + digitIndex
                    ]
                    let packedBase = (component * digitCount + digitIndex) * count
                    for recordIndex in 0..<count {
                        packedDigits[packedBase + recordIndex] = digit
                    }
                }
            }
            return packedDigits
        }
    }
}
