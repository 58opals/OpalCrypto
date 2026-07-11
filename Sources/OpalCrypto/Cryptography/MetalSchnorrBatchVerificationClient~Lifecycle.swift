// MetalSchnorrBatchVerificationClient~Lifecycle.swift

import Foundation

#if canImport(Metal) && canImport(OpalCryptoMetal)
import Metal
import OpalCryptoMetal
#endif

extension MetalSchnorrBatchVerificationClient {
    var executionWaiterCount: Int {
        executionWaiters.count
    }

    func acquireExecution() async throws {
        try Task.checkCancellation()
        guard isExecuting else {
            isExecuting = true
            return
        }

        let identifier = nextExecutionWaiterIdentifier
        nextExecutionWaiterIdentifier &+= 1
        let acquired = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard !Task.isCancelled else {
                    continuation.resume(returning: false)
                    return
                }
                executionWaiters[identifier] = continuation
                executionWaiterOrder.append(identifier)
            }
        } onCancel: {
            Task {
                await self.cancelExecutionWaiter(identifier: identifier)
            }
        }
        guard acquired else {
            throw CancellationError()
        }
        do {
            try Task.checkCancellation()
        } catch {
            releaseExecution()
            throw error
        }
    }

    func releaseExecution() {
        while executionWaiterOrderHead < executionWaiterOrder.count {
            let identifier = executionWaiterOrder[executionWaiterOrderHead]
            executionWaiterOrderHead += 1
            guard let continuation = executionWaiters.removeValue(
                forKey: identifier
            ) else {
                continue
            }
            compactExecutionWaiterOrderIfNeeded()
            continuation.resume(returning: true)
            return
        }
        executionWaiterOrder.removeAll(keepingCapacity: true)
        executionWaiterOrderHead = 0
        isExecuting = false
    }

    func cancelExecutionWaiter(identifier: UInt64) {
        guard let continuation = executionWaiters.removeValue(
            forKey: identifier
        ) else {
            return
        }
        continuation.resume(returning: false)
    }

    private func compactExecutionWaiterOrderIfNeeded() {
        if executionWaiterOrderHead == executionWaiterOrder.count {
            executionWaiterOrder.removeAll(keepingCapacity: true)
            executionWaiterOrderHead = 0
        } else if executionWaiterOrderHead >= 64,
                  executionWaiterOrderHead * 2 >= executionWaiterOrder.count {
            executionWaiterOrder.removeFirst(executionWaiterOrderHead)
            executionWaiterOrderHead = 0
        }
    }

    func initializeRuntimeIfNeeded() throws {
        #if canImport(Metal) && canImport(OpalCryptoMetal)
        guard device == nil else { return }
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw MetalSchnorrBatchVerificationError.unavailable
        }
        guard Self.isCertifiedDevice(device: device) else {
            throw MetalSchnorrBatchVerificationError.uncertifiedDevice
        }
        guard let commandQueue = device.makeCommandQueue() else {
            throw MetalSchnorrBatchVerificationError.unavailable
        }
        let library: any MTLLibrary
        do {
            library = try device.makeDefaultLibrary(
                bundle: MetalShaderLibraryBundle.resource
            )
        } catch {
            throw MetalSchnorrBatchVerificationError.shaderLibraryUnavailable
        }
        guard let cachedKeyFunction = library.makeFunction(
            name: "opal_schnorr_verify_core"
        ),
              let varyingKeyFunction = library.makeFunction(
                name: "opal_schnorr_verify_varying_key"
              )
        else {
            throw MetalSchnorrBatchVerificationError.shaderLibraryUnavailable
        }
        let cachedKeyPipeline: any MTLComputePipelineState
        let varyingKeyPipeline: any MTLComputePipelineState
        do {
            cachedKeyPipeline = try device.makeComputePipelineState(
                function: cachedKeyFunction
            )
            varyingKeyPipeline = try device.makeComputePipelineState(
                function: varyingKeyFunction
            )
        } catch {
            throw MetalSchnorrBatchVerificationError.pipelineCreationFailed
        }
        guard let countBuffer = device.makeBuffer(
            length: MemoryLayout<UInt32>.stride,
            options: .storageModeShared
        ) else {
            throw MetalSchnorrBatchVerificationError.bufferAllocationFailed
        }
        self.device = device
        self.commandQueue = commandQueue
        self.cachedKeyPipeline = cachedKeyPipeline
        self.varyingKeyPipeline = varyingKeyPipeline
        self.countBuffer = countBuffer
        #else
        throw MetalSchnorrBatchVerificationError.unavailable
        #endif
    }

    #if canImport(Metal) && canImport(OpalCryptoMetal)
    nonisolated static func resolveThreadgroupWidth(
        pipeline: any MTLComputePipelineState
    ) -> Int {
        let candidates = [128, 64, 256, 512]
        return candidates.first { width in
            width <= pipeline.maxTotalThreadsPerThreadgroup
                && width.isMultiple(of: pipeline.threadExecutionWidth)
        } ?? min(
            pipeline.maxTotalThreadsPerThreadgroup,
            max(1, pipeline.threadExecutionWidth)
        )
    }
    #endif
}
