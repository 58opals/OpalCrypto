// OpalCryptoBenchmarks+MetalVerificationProbe.swift

extension OpalCryptoBenchmarks {
    enum MetalVerificationProbe {
        static func run(expectedResults: [Bool], seed: UInt32) throws -> Int {
            #if canImport(Metal)
            try MetalVerificationProbeRuntime.shared.run(
                records: makeRecords(expectedResults: expectedResults, seed: seed)
            )
            #else
            throw MetalVerificationProbeError.unavailable
            #endif
        }

        private static func makeRecords(
            expectedResults: [Bool],
            seed: UInt32
        ) -> [MetalVerificationProbeRecord] {
            var records: [MetalVerificationProbeRecord] = .init()
            records.reserveCapacity(expectedResults.count)
            for (index, expectedResult) in expectedResults.enumerated() {
                records.append(
                    MetalVerificationProbeRecord(
                        expected: expectedResult ? 1 : 0,
                        tag: seed &+ UInt32(index)
                    )
                )
            }
            return records
        }
    }
}
