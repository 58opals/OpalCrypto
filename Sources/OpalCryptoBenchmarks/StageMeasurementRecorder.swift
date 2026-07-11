// StageMeasurementRecorder.swift

import Synchronization

final class StageMeasurementRecorder: Sendable {
    private let measurements = Mutex<[
        OpalCryptoBenchmarks.MetalSchnorrVerificationCore.StageMeasurement
    ]>([])

    func append(
        _ measurement: OpalCryptoBenchmarks.MetalSchnorrVerificationCore.StageMeasurement
    ) {
        measurements.withLock {
            $0.append(measurement)
        }
    }

    func reset() {
        measurements.withLock {
            $0.removeAll(keepingCapacity: true)
        }
    }

    func take() -> [
        OpalCryptoBenchmarks.MetalSchnorrVerificationCore.StageMeasurement
    ] {
        measurements.withLock {
            let capturedMeasurements = $0
            $0.removeAll(keepingCapacity: true)
            return capturedMeasurements
        }
    }
}
