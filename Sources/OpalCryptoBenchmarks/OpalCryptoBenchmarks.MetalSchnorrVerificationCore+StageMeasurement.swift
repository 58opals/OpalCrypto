// OpalCryptoBenchmarks.MetalSchnorrVerificationCore+StageMeasurement.swift

import Foundation

extension OpalCryptoBenchmarks.MetalSchnorrVerificationCore {
    struct StageMeasurement: Sendable {
        let keyMode: KeyMode
        let recordCount: Int
        let threadgroupWidth: Int
        let cpuPreparationNanoseconds: UInt64
        let uploadNanoseconds: UInt64
        let dispatchWaitNanoseconds: UInt64
        let readbackValidationNanoseconds: UInt64

        static func combining(_ measurements: [StageMeasurement]) -> StageMeasurement? {
            guard let first = measurements.first else { return nil }
            precondition(
                measurements.allSatisfy {
                    $0.recordCount == first.recordCount
                        && $0.threadgroupWidth == first.threadgroupWidth
                        && $0.keyMode == first.keyMode
                },
                "A benchmark sample cannot combine different Metal workload shapes."
            )
            return StageMeasurement(
                keyMode: first.keyMode,
                recordCount: first.recordCount,
                threadgroupWidth: first.threadgroupWidth,
                cpuPreparationNanoseconds: measurements.reduce(0) {
                    $0 + $1.cpuPreparationNanoseconds
                },
                uploadNanoseconds: measurements.reduce(0) {
                    $0 + $1.uploadNanoseconds
                },
                dispatchWaitNanoseconds: measurements.reduce(0) {
                    $0 + $1.dispatchWaitNanoseconds
                },
                readbackValidationNanoseconds: measurements.reduce(0) {
                    $0 + $1.readbackValidationNanoseconds
                }
            )
        }

        var jsonObject: [String: Any] {
            [
                "key_mode": keyMode.rawValue,
                "record_count": recordCount,
                "threadgroup_width": threadgroupWidth,
                "cpu_preparation_ns": Int64(cpuPreparationNanoseconds),
                "upload_ns": Int64(uploadNanoseconds),
                "dispatch_wait_ns": Int64(dispatchWaitNanoseconds),
                "readback_validation_ns": Int64(readbackValidationNanoseconds)
            ]
        }
    }
}
