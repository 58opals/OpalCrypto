// OpalCryptoBenchmarks.MetalSchnorrVerificationCore+Configuration.swift

import Foundation

extension OpalCryptoBenchmarks.MetalSchnorrVerificationCore {
    struct Configuration: Sendable {
        let deviceName: String
        let appleGPUFamily: String
        let threadExecutionWidth: Int
        let supportedThreadgroupWidths: [Int]
        let selectedThreadgroupWidth: Int
        let pipelineInitializationNanoseconds: UInt64

        var description: String {
            let supported = supportedThreadgroupWidths.map(String.init).joined(separator: ",")
            let initializationMilliseconds = Double(pipelineInitializationNanoseconds)
                / 1_000_000
            return "device=\(deviceName), family=\(appleGPUFamily), "
                + "threadExecutionWidth=\(threadExecutionWidth), "
                + "supportedThreadgroupWidths=[\(supported)], "
                + "selectedThreadgroupWidth=\(selectedThreadgroupWidth), "
                + String(
                    format: "pipelineInitialization=%.3f ms",
                    locale: Locale(identifier: "en_US_POSIX"),
                    initializationMilliseconds
                )
        }
    }
}
