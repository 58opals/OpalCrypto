// MetalSchnorrVerificationRuntime.swift

// The benchmark retains an independent host runtime while loading the same
// packaged shader library as production. Evidence: docs/metal-readiness.md
// and docs/benchmarks.md. Owner: Opal Crypto maintainers.

import Foundation
import OpalCrypto

#if canImport(Metal) && canImport(OpalCryptoMetal)
import Metal
import OpalCryptoMetal
#endif

#if canImport(Metal) && canImport(OpalCryptoMetal)
final class MetalSchnorrVerificationRuntime: @unchecked Sendable {
    private static let sharedResult: Result<MetalSchnorrVerificationRuntime, Swift.Error> = Result {
        try MetalSchnorrVerificationRuntime()
    }
    private static let candidateThreadgroupWidths = [64, 128, 256, 512]
    private static let maximumVerificationRecordCount = 8192
    private static let maximumFieldValidationCaseCount = 10_100

    private let device: MTLDevice
    private let commandQueue: MTLCommandQueue
    private let pipelineState: MTLComputePipelineState
    private let varyingKeyPipelineState: MTLComputePipelineState
    private let fieldValidationPipelineState: MTLComputePipelineState
    private let countBuffer: MTLBuffer
    private let lock = NSLock()

    let configuration: OpalCryptoBenchmarks.MetalSchnorrVerificationCore.Configuration

    private var inputBuffer: MTLBuffer?
    private var digitBuffer: MTLBuffer?
    private var outputBuffer: MTLBuffer?
    private var tableBuffer: MTLBuffer?
    private var cachedTableWords: [UInt32] = []
    private var sharedGeneratorTableBuffer: MTLBuffer?
    private var cachedSharedGeneratorTableWords: [UInt32] = []
    private var varyingVerificationKeyTableBuffer: MTLBuffer?
    private var cachedVaryingTableIdentifier: UUID?
    private var cachedVaryingTableByteCount = 0

    static func instance() throws -> MetalSchnorrVerificationRuntime {
        try sharedResult.get()
    }

    private init() throws {
        let initializationStart = DispatchTime.now().uptimeNanoseconds
        guard let device = MTLCreateSystemDefaultDevice(),
              let commandQueue = device.makeCommandQueue()
        else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }
        self.device = device
        self.commandQueue = commandQueue
        let library = try device.makeDefaultLibrary(
            bundle: MetalShaderLibraryBundle.resource
        )
        guard let function = library.makeFunction(name: "opal_schnorr_verify_core"),
              let varyingKeyFunction = library.makeFunction(
                  name: "opal_schnorr_verify_varying_key"
              ),
              let fieldValidationFunction = library.makeFunction(name: "opal_field_validation"),
              let countBuffer = device.makeBuffer(
                  length: MemoryLayout<UInt32>.stride,
                  options: .storageModeShared
              )
        else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }
        let pipelineState = try device.makeComputePipelineState(function: function)
        let varyingKeyPipelineState = try device.makeComputePipelineState(
            function: varyingKeyFunction
        )
        let fieldValidationPipelineState = try device.makeComputePipelineState(
            function: fieldValidationFunction
        )
        self.pipelineState = pipelineState
        self.varyingKeyPipelineState = varyingKeyPipelineState
        self.fieldValidationPipelineState = fieldValidationPipelineState
        self.countBuffer = countBuffer

        let supportedThreadgroupWidths = Self.candidateThreadgroupWidths.filter { width in
            width <= pipelineState.maxTotalThreadsPerThreadgroup
                && width.isMultiple(of: pipelineState.threadExecutionWidth)
        }
        let fallbackWidth = supportedThreadgroupWidths.last
            ?? min(
                pipelineState.maxTotalThreadsPerThreadgroup,
                max(1, pipelineState.threadExecutionWidth)
            )
        let defaultWidth = supportedThreadgroupWidths.contains(128) ? 128 : fallbackWidth
        let environmentWidth = ProcessInfo.processInfo.environment[
            "OPALCRYPTO_METAL_THREADGROUP_WIDTH"
        ].flatMap(Int.init)
        let selectedWidth = environmentWidth.flatMap { requestedWidth in
            supportedThreadgroupWidths.contains(requestedWidth) ? requestedWidth : nil
        } ?? defaultWidth
        configuration = OpalCryptoBenchmarks.MetalSchnorrVerificationCore.Configuration(
            deviceName: device.name,
            appleGPUFamily: Self.appleGPUFamilyDescription(device: device),
            threadExecutionWidth: pipelineState.threadExecutionWidth,
            supportedThreadgroupWidths: supportedThreadgroupWidths,
            selectedThreadgroupWidth: selectedWidth,
            pipelineInitializationNanoseconds: DispatchTime.now().uptimeNanoseconds
                - initializationStart
        )
    }

    func run(
        recordWords: [UInt32],
        packedDigits: [Int8],
        tableWords: [UInt32],
        expectedResults: [UInt32],
        recordCount: Int,
        requestedThreadgroupWidth: Int?,
        cpuPreparationNanoseconds: UInt64
    ) throws -> Int {
        guard recordCount > 0 else { return 0 }
        precondition(recordCount <= Self.maximumVerificationRecordCount)
        precondition(recordWords.count == recordCount * 8)
        precondition(packedDigits.count == recordCount * 4 * 130)
        precondition(tableWords.count == 4 * 32 * 16)
        precondition(expectedResults.count == recordCount)

        lock.lock()
        defer { lock.unlock() }

        let uploadStart = DispatchTime.now().uptimeNanoseconds
        let inputByteCount = recordWords.count * MemoryLayout<UInt32>.stride
        let digitByteCount = packedDigits.count * MemoryLayout<Int8>.stride
        let outputByteCount = recordCount * MemoryLayout<UInt32>.stride
        let inputBuffer = try ensureBuffer(
            &self.inputBuffer,
            minimumByteCount: inputByteCount
        )
        let digitBuffer = try ensureBuffer(
            &self.digitBuffer,
            minimumByteCount: digitByteCount
        )
        let outputBuffer = try ensureBuffer(
            &self.outputBuffer,
            minimumByteCount: outputByteCount
        )
        let tableBuffer = try cachedTableBuffer(for: tableWords)
        copy(recordWords, byteCount: inputByteCount, to: inputBuffer)
        copy(packedDigits, byteCount: digitByteCount, to: digitBuffer)
        // SAFETY: countBuffer owns at least one UInt32 and remains alive through completion.
        countBuffer.contents().assumingMemoryBound(to: UInt32.self).pointee = UInt32(recordCount)
        let uploadNanoseconds = DispatchTime.now().uptimeNanoseconds - uploadStart

        guard let commandBuffer = commandQueue.makeCommandBuffer(),
            let encoder = commandBuffer.makeComputeCommandEncoder()
        else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }

        let threadgroupWidth = resolveThreadgroupWidth(requestedThreadgroupWidth)
        commandBuffer.label = "OpalCrypto Schnorr cached-key \(recordCount)"
        encoder.label = "OpalCrypto Schnorr verify \(recordCount)"

        encoder.setComputePipelineState(pipelineState)
        encoder.setBuffer(inputBuffer, offset: 0, index: 0)
        encoder.setBuffer(outputBuffer, offset: 0, index: 1)
        encoder.setBuffer(countBuffer, offset: 0, index: 2)
        encoder.setBuffer(tableBuffer, offset: 0, index: 3)
        encoder.setBuffer(digitBuffer, offset: 0, index: 4)

        let threadCount = MTLSize(width: recordCount, height: 1, depth: 1)
        let threadsPerThreadgroup = MTLSize(
            width: threadgroupWidth,
            height: 1,
            depth: 1
        )
        encoder.dispatchThreads(
            threadCount,
            threadsPerThreadgroup: threadsPerThreadgroup
        )
        encoder.endEncoding()
        let gpuStart = DispatchTime.now().uptimeNanoseconds
        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()
        let gpuNanoseconds = DispatchTime.now().uptimeNanoseconds - gpuStart

        guard commandBuffer.status == .completed else {
            let message = commandBuffer.error?.localizedDescription
                ?? "unexpected command-buffer status \(commandBuffer.status.rawValue)"
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.commandBufferFailed(message)
        }

        let readbackStart = DispatchTime.now().uptimeNanoseconds
        // SAFETY: outputBuffer is shared, completed, and at least recordCount UInt32 values long.
        let output = outputBuffer.contents().bindMemory(
            to: UInt32.self,
            capacity: recordCount
        )
        var checksum = 0
        for index in 0..<recordCount {
            guard output[index] == expectedResults[index] else {
                throw OpalCryptoBenchmarks.MetalVerificationProbeError.invalidResult(index: index)
            }
            checksum ^= Int(output[index]) &+ index
        }
        let readbackNanoseconds = DispatchTime.now().uptimeNanoseconds - readbackStart
        OpalCryptoBenchmarks.MetalSchnorrVerificationCore.recordStageMeasurement(
            OpalCryptoBenchmarks.MetalSchnorrVerificationCore.StageMeasurement(
                keyMode: .cached,
                recordCount: recordCount,
                threadgroupWidth: threadgroupWidth,
                cpuPreparationNanoseconds: cpuPreparationNanoseconds,
                uploadNanoseconds: uploadNanoseconds,
                dispatchWaitNanoseconds: gpuNanoseconds,
                readbackValidationNanoseconds: readbackNanoseconds
            )
        )
        return checksum
    }

    func run(
        varyingKeyRecordWords: [UInt32],
        packedDigits: [Int8],
        sharedGeneratorTableWords: [UInt32],
        varyingVerificationKeyTableWords: [UInt32],
        expectedResults: [UInt32],
        recordCount: Int,
        tableCacheIdentifier: UUID,
        requestedThreadgroupWidth: Int?,
        cpuPreparationNanoseconds: UInt64
    ) throws -> Int {
        guard recordCount > 0 else { return 0 }
        precondition(recordCount <= Self.maximumVerificationRecordCount)
        precondition(varyingKeyRecordWords.count == recordCount * 8)
        precondition(packedDigits.count == recordCount * 4 * 130)
        precondition(sharedGeneratorTableWords.count == 2 * 32 * 16)
        precondition(
            varyingVerificationKeyTableWords.count
                == recordCount * PerformanceBenchmarkOperations
                    .metalSchnorrVaryingVerificationKeyTableSlotCount
        )
        precondition(expectedResults.count == recordCount)

        lock.lock()
        defer { lock.unlock() }

        let uploadStart = DispatchTime.now().uptimeNanoseconds
        let inputByteCount = varyingKeyRecordWords.count * MemoryLayout<UInt32>.stride
        let digitByteCount = packedDigits.count * MemoryLayout<Int8>.stride
        let outputByteCount = recordCount * MemoryLayout<UInt32>.stride
        let inputBuffer = try ensureBuffer(
            &self.inputBuffer,
            minimumByteCount: inputByteCount
        )
        let digitBuffer = try ensureBuffer(
            &self.digitBuffer,
            minimumByteCount: digitByteCount
        )
        let outputBuffer = try ensureBuffer(
            &self.outputBuffer,
            minimumByteCount: outputByteCount
        )
        let sharedGeneratorTableBuffer = try cachedSharedGeneratorTableBuffer(
            for: sharedGeneratorTableWords
        )
        let varyingVerificationKeyTableBuffer = try cachedVaryingVerificationKeyTableBuffer(
            for: varyingVerificationKeyTableWords,
            identifier: tableCacheIdentifier
        )
        copy(varyingKeyRecordWords, byteCount: inputByteCount, to: inputBuffer)
        copy(packedDigits, byteCount: digitByteCount, to: digitBuffer)
        // SAFETY: countBuffer owns one UInt32 and the runtime lock excludes concurrent writes.
        countBuffer.contents().assumingMemoryBound(to: UInt32.self).pointee = UInt32(recordCount)
        let uploadNanoseconds = DispatchTime.now().uptimeNanoseconds - uploadStart

        guard let commandBuffer = commandQueue.makeCommandBuffer(),
              let encoder = commandBuffer.makeComputeCommandEncoder()
        else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }

        let threadgroupWidth = resolveThreadgroupWidth(
            requestedThreadgroupWidth,
            pipelineState: varyingKeyPipelineState
        )
        commandBuffer.label = "OpalCrypto Schnorr varying-key \(recordCount)"
        encoder.label = "OpalCrypto Schnorr varying-key verify \(recordCount)"
        encoder.setComputePipelineState(varyingKeyPipelineState)
        encoder.setBuffer(inputBuffer, offset: 0, index: 0)
        encoder.setBuffer(outputBuffer, offset: 0, index: 1)
        encoder.setBuffer(countBuffer, offset: 0, index: 2)
        encoder.setBuffer(sharedGeneratorTableBuffer, offset: 0, index: 3)
        encoder.setBuffer(varyingVerificationKeyTableBuffer, offset: 0, index: 4)
        encoder.setBuffer(digitBuffer, offset: 0, index: 5)
        encoder.dispatchThreads(
            MTLSize(width: recordCount, height: 1, depth: 1),
            threadsPerThreadgroup: MTLSize(
                width: threadgroupWidth,
                height: 1,
                depth: 1
            )
        )
        encoder.endEncoding()
        let gpuStart = DispatchTime.now().uptimeNanoseconds
        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()
        let gpuNanoseconds = DispatchTime.now().uptimeNanoseconds - gpuStart

        guard commandBuffer.status == .completed else {
            let message = commandBuffer.error?.localizedDescription
                ?? "unexpected command-buffer status \(commandBuffer.status.rawValue)"
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.commandBufferFailed(message)
        }

        let readbackStart = DispatchTime.now().uptimeNanoseconds
        // SAFETY: outputBuffer is shared, completed, and covers recordCount UInt32 values.
        let output = outputBuffer.contents().bindMemory(
            to: UInt32.self,
            capacity: recordCount
        )
        var checksum = 0
        for index in 0..<recordCount {
            guard output[index] == expectedResults[index] else {
                throw OpalCryptoBenchmarks.MetalVerificationProbeError.invalidResult(index: index)
            }
            checksum ^= Int(output[index]) &+ index
        }
        let readbackNanoseconds = DispatchTime.now().uptimeNanoseconds - readbackStart
        OpalCryptoBenchmarks.MetalSchnorrVerificationCore.recordStageMeasurement(
            OpalCryptoBenchmarks.MetalSchnorrVerificationCore.StageMeasurement(
                keyMode: .varying,
                recordCount: recordCount,
                threadgroupWidth: threadgroupWidth,
                cpuPreparationNanoseconds: cpuPreparationNanoseconds,
                uploadNanoseconds: uploadNanoseconds,
                dispatchWaitNanoseconds: gpuNanoseconds,
                readbackValidationNanoseconds: readbackNanoseconds
            )
        )
        return checksum
    }

    func validateFieldOperations(
        _ cases: [MetalFieldValidationBenchmarkCase]
    ) throws -> Int {
        guard !cases.isEmpty else { return 0 }
        precondition(cases.count <= Self.maximumFieldValidationCaseCount)

        var inputWords: [UInt32] = .init()
        inputWords.reserveCapacity(cases.count * 16)
        for validationCase in cases {
            precondition(validationCase.leftWords.count == 8)
            precondition(validationCase.rightWords.count == 8)
            precondition(validationCase.expectedProductWords.count == 8)
            precondition(validationCase.expectedSquareWords.count == 8)
            inputWords.append(contentsOf: validationCase.leftWords)
            inputWords.append(contentsOf: validationCase.rightWords)
        }

        lock.lock()
        defer { lock.unlock() }

        let inputByteCount = inputWords.count * MemoryLayout<UInt32>.stride
        let outputWordCount = cases.count * 17
        let outputByteCount = outputWordCount * MemoryLayout<UInt32>.stride
        guard let inputBuffer = device.makeBuffer(
            length: inputByteCount,
            options: .storageModeShared
        ),
            let outputBuffer = device.makeBuffer(
                length: outputByteCount,
                options: .storageModeShared
            ),
            let commandBuffer = commandQueue.makeCommandBuffer(),
            let encoder = commandBuffer.makeComputeCommandEncoder()
        else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }
        copy(inputWords, byteCount: inputByteCount, to: inputBuffer)
        // SAFETY: countBuffer owns at least one UInt32 and validation holds the runtime lock.
        countBuffer.contents().assumingMemoryBound(to: UInt32.self).pointee = UInt32(cases.count)

        commandBuffer.label = "OpalCrypto field differential \(cases.count)"
        encoder.label = "OpalCrypto field validation \(cases.count)"
        encoder.setComputePipelineState(fieldValidationPipelineState)
        encoder.setBuffer(inputBuffer, offset: 0, index: 0)
        encoder.setBuffer(outputBuffer, offset: 0, index: 1)
        encoder.setBuffer(countBuffer, offset: 0, index: 2)
        encoder.dispatchThreads(
            MTLSize(width: cases.count, height: 1, depth: 1),
            threadsPerThreadgroup: MTLSize(
                width: configuration.selectedThreadgroupWidth,
                height: 1,
                depth: 1
            )
        )
        encoder.endEncoding()
        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()

        guard commandBuffer.status == .completed else {
            let message = commandBuffer.error?.localizedDescription
                ?? "unexpected command-buffer status \(commandBuffer.status.rawValue)"
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.commandBufferFailed(message)
        }

        // SAFETY: outputBuffer is shared, completed, and exactly outputWordCount UInt32 values long.
        let output = outputBuffer.contents().bindMemory(
            to: UInt32.self,
            capacity: outputWordCount
        )
        var checksum = 0
        for (index, validationCase) in cases.enumerated() {
            let outputBase = index * 17
            for limb in 0..<8 {
                guard output[outputBase + limb] == validationCase.expectedProductWords[limb],
                      output[outputBase + 8 + limb] == validationCase.expectedSquareWords[limb]
                else {
                    throw OpalCryptoBenchmarks.MetalVerificationProbeError.invalidResult(
                        index: index
                    )
                }
            }
            guard output[outputBase + 16] == validationCase.expectedQuadraticResidue else {
                throw OpalCryptoBenchmarks.MetalVerificationProbeError.invalidResult(index: index)
            }
            checksum ^= Int(output[outputBase]) &+ Int(output[outputBase + 8]) &+ index
        }
        return checksum
    }

    private func ensureBuffer(
        _ buffer: inout MTLBuffer?,
        minimumByteCount: Int
    ) throws -> MTLBuffer {
        if let buffer, buffer.length >= minimumByteCount {
            return buffer
        }
        guard let replacement = device.makeBuffer(
            length: Self.roundedBufferByteCount(minimumByteCount),
            options: .storageModeShared
        ) else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }
        buffer = replacement
        return replacement
    }

    private func cachedTableBuffer(for tableWords: [UInt32]) throws -> MTLBuffer {
        if let tableBuffer, cachedTableWords == tableWords {
            return tableBuffer
        }
        let byteCount = tableWords.count * MemoryLayout<UInt32>.stride
        guard let replacement = device.makeBuffer(
            length: byteCount,
            options: .storageModeShared
        ) else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }
        copy(tableWords, byteCount: byteCount, to: replacement)
        cachedTableWords = tableWords
        tableBuffer = replacement
        return replacement
    }

    private func cachedSharedGeneratorTableBuffer(
        for tableWords: [UInt32]
    ) throws -> MTLBuffer {
        if let sharedGeneratorTableBuffer,
           cachedSharedGeneratorTableWords == tableWords {
            return sharedGeneratorTableBuffer
        }
        let byteCount = tableWords.count * MemoryLayout<UInt32>.stride
        guard let replacement = device.makeBuffer(
            length: byteCount,
            options: .storageModeShared
        ) else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }
        copy(tableWords, byteCount: byteCount, to: replacement)
        cachedSharedGeneratorTableWords = tableWords
        sharedGeneratorTableBuffer = replacement
        return replacement
    }

    private func cachedVaryingVerificationKeyTableBuffer(
        for tableWords: [UInt32],
        identifier: UUID
    ) throws -> MTLBuffer {
        let byteCount = tableWords.count * MemoryLayout<UInt32>.stride
        let buffer = try ensureBuffer(
            &varyingVerificationKeyTableBuffer,
            minimumByteCount: byteCount
        )
        if cachedVaryingTableIdentifier == identifier {
            precondition(
                cachedVaryingTableByteCount == byteCount,
                "A varying-key table cache identifier cannot change table shape."
            )
            return buffer
        }
        copy(tableWords, byteCount: byteCount, to: buffer)
        cachedVaryingTableIdentifier = identifier
        cachedVaryingTableByteCount = byteCount
        return buffer
    }

    private func copy<Element>(
        _ values: [Element],
        byteCount: Int,
        to buffer: MTLBuffer
    ) {
        precondition(byteCount <= buffer.length)
        values.withUnsafeBufferPointer { source in
            guard let sourceAddress = source.baseAddress else { return }
            // SAFETY: source covers byteCount bytes and buffer was capacity-checked above.
            buffer.contents().copyMemory(from: sourceAddress, byteCount: byteCount)
        }
    }

    private func resolveThreadgroupWidth(_ requestedWidth: Int?) -> Int {
        guard let requestedWidth else { return configuration.selectedThreadgroupWidth }
        precondition(
            configuration.supportedThreadgroupWidths.contains(requestedWidth),
            "Threadgroup width must be one of the reported aligned candidates."
        )
        return requestedWidth
    }

    private func resolveThreadgroupWidth(
        _ requestedWidth: Int?,
        pipelineState: MTLComputePipelineState
    ) -> Int {
        let resolvedWidth = requestedWidth ?? configuration.selectedThreadgroupWidth
        precondition(
            Self.candidateThreadgroupWidths.contains(resolvedWidth)
                && resolvedWidth <= pipelineState.maxTotalThreadsPerThreadgroup
                && resolvedWidth.isMultiple(of: pipelineState.threadExecutionWidth),
            "Threadgroup width must be an aligned candidate supported by this pipeline."
        )
        return resolvedWidth
    }

    private static func roundedBufferByteCount(_ minimumByteCount: Int) -> Int {
        precondition(minimumByteCount > 0)
        var byteCount = 256
        while byteCount < minimumByteCount {
            byteCount *= 2
        }
        return byteCount
    }

    private static func appleGPUFamilyDescription(device: MTLDevice) -> String {
        if device.supportsFamily(.apple10) { return "Apple 10" }
        if device.supportsFamily(.apple9) { return "Apple 9" }
        if device.supportsFamily(.apple8) { return "Apple 8" }
        if device.supportsFamily(.apple7) { return "Apple 7" }
        if device.supportsFamily(.apple6) { return "Apple 6" }
        if device.supportsFamily(.apple5) { return "Apple 5" }
        if device.supportsFamily(.apple4) { return "Apple 4" }
        if device.supportsFamily(.apple3) { return "Apple 3" }
        if device.supportsFamily(.apple2) { return "Apple 2" }
        if device.supportsFamily(.apple1) { return "Apple 1" }
        return "unknown"
    }
}
#endif
