// MetalSchnorrBatchVerificationClient.swift

import Foundation

#if canImport(Metal) && canImport(OpalCryptoMetal)
import Metal
import OpalCryptoMetal
#endif

actor MetalSchnorrBatchVerificationClient {
    static let shared = MetalSchnorrBatchVerificationClient()
    static let maximumTemporaryBufferByteCount = 32 * 1_024 * 1_024

    nonisolated static var isCertifiedDeviceAvailable: Bool {
        #if os(macOS) && canImport(Metal) && canImport(OpalCryptoMetal)
        guard let device = MTLCreateSystemDefaultDevice() else { return false }
        return isCertifiedDevice(device: device)
        #else
        return false
        #endif
    }

    #if canImport(Metal) && canImport(OpalCryptoMetal)
    var device: (any MTLDevice)?
    var commandQueue: (any MTLCommandQueue)?
    var cachedKeyPipeline: (any MTLComputePipelineState)?
    var varyingKeyPipeline: (any MTLComputePipelineState)?
    var countBuffer: (any MTLBuffer)?
    var inputBuffer: (any MTLBuffer)?
    var digitBuffer: (any MTLBuffer)?
    var outputBuffer: (any MTLBuffer)?
    var cachedKeyTableBuffer: (any MTLBuffer)?
    var sharedGeneratorTableBuffer: (any MTLBuffer)?
    var varyingKeyTableBuffer: (any MTLBuffer)?
    var cachedKeyTableIdentifier: Data?
    var cachedSharedGeneratorTableWords: [UInt32]?
    #endif

    var hasPassedSelfTest = false
    var isQuarantined = false
    var isExecuting = false
    var executionWaiters: [UInt64: CheckedContinuation<Bool, Never>] = [:]
    var executionWaiterOrder: [UInt64] = []
    var executionWaiterOrderHead = 0
    var nextExecutionWaiterIdentifier: UInt64 = 0

    init() {}

    #if canImport(Metal) && canImport(OpalCryptoMetal)
    nonisolated static func isCertifiedDevice(device: any MTLDevice) -> Bool {
        #if os(macOS)
        device.name == "Apple M1 Max" && device.supportsFamily(.apple7)
        #else
        false
        #endif
    }
    #endif
}
