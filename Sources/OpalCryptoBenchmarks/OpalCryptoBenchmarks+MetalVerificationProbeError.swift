// OpalCryptoBenchmarks+MetalVerificationProbeError.swift

extension OpalCryptoBenchmarks {
    enum MetalVerificationProbeError: Error, CustomStringConvertible {
        case unavailable
        case invalidResult(index: Int)
        case commandBufferFailed(String)

        var description: String {
            switch self {
            case .unavailable:
                "Metal is not available on this platform."
            case .invalidResult(let index):
                "Metal verification probe produced an invalid result at index \(index)."
            case .commandBufferFailed(let message):
                "Metal verification probe command buffer failed: \(message)"
            }
        }
    }
}
