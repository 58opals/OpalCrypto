// OpalCryptoBenchmarks+BenchmarkRunEnvironment.swift

import Foundation

#if canImport(Metal)
import Metal
#endif

extension OpalCryptoBenchmarks {
    struct BenchmarkRunEnvironment {
        let activeProcessorCount: Int
        let lowPowerMode: String
        let thermalState: String
        let metalCoreConfiguration: MetalSchnorrVerificationCore.Configuration?

        #if canImport(Metal)
        let metalDeviceName: String?
        let metalAppleGPUFamily: String?
        #endif

        static func make(
            metalCoreConfiguration: MetalSchnorrVerificationCore.Configuration?
        ) -> BenchmarkRunEnvironment {
            let processInfo = ProcessInfo.processInfo

            #if canImport(Metal)
            let metalDevice = MTLCreateSystemDefaultDevice()
            return BenchmarkRunEnvironment(
                activeProcessorCount: processInfo.activeProcessorCount,
                lowPowerMode: processInfo.isLowPowerModeEnabled ? "enabled" : "disabled",
                thermalState: thermalStateName(processInfo.thermalState),
                metalCoreConfiguration: metalCoreConfiguration,
                metalDeviceName: metalDevice?.name,
                metalAppleGPUFamily: metalDevice.flatMap(bestSupportedAppleGPUFamily)
            )
            #else
            return BenchmarkRunEnvironment(
                activeProcessorCount: processInfo.activeProcessorCount,
                lowPowerMode: processInfo.isLowPowerModeEnabled ? "enabled" : "disabled",
                thermalState: thermalStateName(processInfo.thermalState),
                metalCoreConfiguration: metalCoreConfiguration
            )
            #endif
        }

        var jsonObject: [String: Any] {
            var object: [String: Any] = [
                "active_processor_count": activeProcessorCount,
                "low_power_mode": lowPowerMode,
                "thermal_state": thermalState
            ]

            #if canImport(Metal)
            object["metal_device_name"] = metalDeviceName ?? NSNull()
            object["metal_apple_gpu_family"] = metalAppleGPUFamily ?? NSNull()
            #endif

            if let metalCoreConfiguration {
                object["metal_core_pipeline_cold_initialization_ns"] = Int64(
                    metalCoreConfiguration.pipelineInitializationNanoseconds
                )
                object["metal_core_thread_execution_width"] =
                    metalCoreConfiguration.threadExecutionWidth
                object["metal_core_supported_threadgroup_widths"] =
                    metalCoreConfiguration.supportedThreadgroupWidths
                object["metal_core_selected_threadgroup_width"] =
                    metalCoreConfiguration.selectedThreadgroupWidth
            }

            return object
        }

        private static func thermalStateName(_ thermalState: ProcessInfo.ThermalState) -> String {
            switch thermalState {
            case .nominal:
                "nominal"
            case .fair:
                "fair"
            case .serious:
                "serious"
            case .critical:
                "critical"
            @unknown default:
                "unknown"
            }
        }

        #if canImport(Metal)
        private static func bestSupportedAppleGPUFamily(_ device: any MTLDevice) -> String? {
            if device.supportsFamily(.apple10) {
                return "apple10"
            }
            if device.supportsFamily(.apple9) {
                return "apple9"
            }
            if device.supportsFamily(.apple8) {
                return "apple8"
            }
            if device.supportsFamily(.apple7) {
                return "apple7"
            }
            return nil
        }
        #endif
    }
}
