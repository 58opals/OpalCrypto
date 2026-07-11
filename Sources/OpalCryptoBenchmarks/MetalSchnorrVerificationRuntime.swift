// MetalSchnorrVerificationRuntime.swift

import Foundation
import OpalCrypto

#if canImport(Metal)
import Metal
#endif

#if canImport(Metal)
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
        let library = try device.makeLibrary(
            source: Self.kernelSource,
            options: nil
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

    private static let kernelSource = """
    #include <metal_stdlib>
    using namespace metal;

    struct U256 {
        uint v[8];
    };

    struct AddResult {
        U256 value;
        uint carry;
    };

    struct SubResult {
        U256 value;
        uint borrow;
    };

    struct Point {
        U256 x;
        U256 y;
        U256 z;
        bool infinity;
    };

    inline U256 u256_zero() {
        U256 r;
        for (uint i = 0; i < 8; i++) {
            r.v[i] = 0u;
        }
        return r;
    }

    inline U256 u256_one() {
        U256 r = u256_zero();
        r.v[0] = 1u;
        return r;
    }

    inline U256 field_p() {
        U256 r;
        r.v[0] = 0xfffffc2fu;
        r.v[1] = 0xfffffffeu;
        r.v[2] = 0xffffffffu;
        r.v[3] = 0xffffffffu;
        r.v[4] = 0xffffffffu;
        r.v[5] = 0xffffffffu;
        r.v[6] = 0xffffffffu;
        r.v[7] = 0xffffffffu;
        return r;
    }

    inline int u256_cmp(U256 a, U256 b) {
        for (int i = 7; i >= 0; i--) {
            if (a.v[i] < b.v[i]) {
                return -1;
            }
            if (a.v[i] > b.v[i]) {
                return 1;
            }
        }
        return 0;
    }

    inline bool u256_equal(U256 a, U256 b) {
        uint difference = 0u;
        for (uint i = 0; i < 8; i++) {
            difference |= a.v[i] ^ b.v[i];
        }
        return difference == 0u;
    }

    inline bool u256_is_zero(U256 a) {
        uint combined = 0u;
        for (uint i = 0; i < 8; i++) {
            combined |= a.v[i];
        }
        return combined == 0u;
    }

    inline AddResult u256_add_raw(U256 a, U256 b) {
        AddResult result;
        ulong carry = 0ul;
        for (uint i = 0; i < 8; i++) {
            ulong sum = ulong(a.v[i]) + ulong(b.v[i]) + carry;
            result.value.v[i] = uint(sum & 0xfffffffful);
            carry = sum >> 32;
        }
        result.carry = uint(carry);
        return result;
    }

    inline SubResult u256_sub_raw(U256 a, U256 b) {
        SubResult result;
        ulong borrow = 0ul;
        for (uint i = 0; i < 8; i++) {
            ulong left = ulong(a.v[i]);
            ulong right = ulong(b.v[i]) + borrow;
            if (left < right) {
                result.value.v[i] = uint((0x100000000ul + left - right) & 0xfffffffful);
                borrow = 1ul;
            } else {
                result.value.v[i] = uint(left - right);
                borrow = 0ul;
            }
        }
        result.borrow = uint(borrow);
        return result;
    }

    inline U256 field_add(U256 a, U256 b) {
        U256 p = field_p();
        AddResult added = u256_add_raw(a, b);
        U256 result = added.value;
        if (added.carry != 0u || u256_cmp(result, p) >= 0) {
            result = u256_sub_raw(result, p).value;
        }
        return result;
    }

    inline U256 field_sub(U256 a, U256 b) {
        U256 p = field_p();
        SubResult subtracted = u256_sub_raw(a, b);
        U256 result = subtracted.value;
        if (subtracted.borrow != 0u) {
            result = u256_add_raw(result, p).value;
        }
        return result;
    }

    inline U256 field_negate(U256 value) {
        if (u256_is_zero(value)) {
            return value;
        }
        return field_sub(u256_zero(), value);
    }

    inline U256 field_double(U256 a) {
        return field_add(a, a);
    }

    inline void comba_add(
        thread ulong *accumulatorLow,
        thread ulong *accumulatorHigh,
        ulong value
    ) {
        ulong previousLow = *accumulatorLow;
        *accumulatorLow += value;
        *accumulatorHigh += ulong(*accumulatorLow < previousLow);
    }

    inline void multiply_comba(U256 a, U256 b, thread uint *productWords) {
        ulong carry = 0ul;
        for (uint diagonal = 0u; diagonal < 15u; diagonal++) {
            ulong accumulatorLow = carry;
            ulong accumulatorHigh = 0ul;
            uint first = diagonal > 7u ? diagonal - 7u : 0u;
            uint last = min(diagonal, 7u);
            for (uint leftIndex = first; leftIndex <= last; leftIndex++) {
                uint rightIndex = diagonal - leftIndex;
                comba_add(
                    &accumulatorLow,
                    &accumulatorHigh,
                    ulong(a.v[leftIndex]) * ulong(b.v[rightIndex])
                );
            }
            productWords[diagonal] = uint(accumulatorLow);
            carry = (accumulatorLow >> 32) | (accumulatorHigh << 32);
        }
        productWords[15] = uint(carry);
    }

    inline void square_comba(U256 value, thread uint *productWords) {
        ulong carry = 0ul;
        for (uint diagonal = 0u; diagonal < 15u; diagonal++) {
            ulong accumulatorLow = carry;
            ulong accumulatorHigh = 0ul;
            uint first = diagonal > 7u ? diagonal - 7u : 0u;
            uint last = min(diagonal, 7u);
            for (uint leftIndex = first; leftIndex <= last; leftIndex++) {
                uint rightIndex = diagonal - leftIndex;
                if (leftIndex > rightIndex) {
                    continue;
                }
                ulong product = ulong(value.v[leftIndex]) * ulong(value.v[rightIndex]);
                comba_add(&accumulatorLow, &accumulatorHigh, product);
                if (leftIndex != rightIndex) {
                    // Add twice instead of shifting: a 32x32 product can need 65 bits when doubled.
                    comba_add(&accumulatorLow, &accumulatorHigh, product);
                }
            }
            productWords[diagonal] = uint(accumulatorLow);
            carry = (accumulatorLow >> 32) | (accumulatorHigh << 32);
        }
        productWords[15] = uint(carry);
    }

    inline U256 reduce_secp256k1_product(thread const uint *productWords) {
        // For p = 2^256 - 2^32 - 977, every high limb can be folded with
        // 2^256 == 2^32 + 977 (mod p). The fixed folds below replace the old
        // data-dependent carry walk and leave at most one final subtraction.
        ulong firstFold[10];
        for (uint index = 0u; index < 10u; index++) {
            firstFold[index] = 0ul;
        }
        for (uint index = 0u; index < 8u; index++) {
            ulong high = ulong(productWords[index + 8u]);
            firstFold[index] += ulong(productWords[index]) + high * 977ul;
            firstFold[index + 1u] += high;
        }

        uint firstFoldWords[10];
        ulong carry = 0ul;
        for (uint index = 0u; index < 10u; index++) {
            ulong accumulator = firstFold[index] + carry;
            firstFoldWords[index] = uint(accumulator);
            carry = accumulator >> 32;
        }

        ulong secondFold[9];
        for (uint index = 0u; index < 9u; index++) {
            secondFold[index] = index < 8u ? ulong(firstFoldWords[index]) : 0ul;
        }
        for (uint index = 0u; index < 2u; index++) {
            ulong high = ulong(firstFoldWords[index + 8u]);
            secondFold[index] += high * 977ul;
            secondFold[index + 1u] += high;
        }

        uint reducedWords[9];
        carry = 0ul;
        for (uint index = 0u; index < 9u; index++) {
            ulong accumulator = secondFold[index] + carry;
            reducedWords[index] = uint(accumulator);
            carry = accumulator >> 32;
        }

        // The second fold leaves only a single carry limb. Two fixed folds are
        // sufficient even when adding the first carry crosses 2^256 again.
        for (uint pass = 0u; pass < 2u; pass++) {
            ulong high = ulong(reducedWords[8]);
            reducedWords[8] = 0u;
            ulong accumulator = ulong(reducedWords[0]) + high * 977ul;
            reducedWords[0] = uint(accumulator);
            carry = accumulator >> 32;
            accumulator = ulong(reducedWords[1]) + high + carry;
            reducedWords[1] = uint(accumulator);
            carry = accumulator >> 32;
            for (uint index = 2u; index < 9u; index++) {
                accumulator = ulong(reducedWords[index]) + carry;
                reducedWords[index] = uint(accumulator);
                carry = accumulator >> 32;
            }
        }

        U256 result;
        for (uint index = 0u; index < 8u; index++) {
            result.v[index] = reducedWords[index];
        }
        U256 p = field_p();
        if (u256_cmp(result, p) >= 0) {
            result = u256_sub_raw(result, p).value;
        }
        return result;
    }

    inline U256 field_mul(U256 a, U256 b) {
        uint productWords[16];
        multiply_comba(a, b, productWords);
        return reduce_secp256k1_product(productWords);
    }

    inline U256 field_square(U256 value) {
        uint productWords[16];
        square_comba(value, productWords);
        return reduce_secp256k1_product(productWords);
    }

    inline U256 field_square_repeated(U256 value, uint count) {
        for (uint index = 0u; index < count; index++) {
            value = field_square(value);
        }
        return value;
    }

    inline U256 field_sqrt_candidate(U256 value) {
        // Fixed addition chain for (p + 1) / 4. A value is a residue exactly
        // when squaring this candidate returns the original field element.
        U256 x2 = field_mul(field_square(value), value);
        U256 x3 = field_mul(field_square(x2), value);
        U256 x6 = field_mul(field_square_repeated(x3, 3u), x3);
        U256 x9 = field_mul(field_square_repeated(x6, 3u), x3);
        U256 x11 = field_mul(field_square_repeated(x9, 2u), x2);
        U256 x22 = field_mul(field_square_repeated(x11, 11u), x11);
        U256 x44 = field_mul(field_square_repeated(x22, 22u), x22);
        U256 x88 = field_mul(field_square_repeated(x44, 44u), x44);
        U256 x176 = field_mul(field_square_repeated(x88, 88u), x88);
        U256 x220 = field_mul(field_square_repeated(x176, 44u), x44);
        U256 x223 = field_mul(field_square_repeated(x220, 3u), x3);
        U256 result = field_mul(field_square_repeated(x223, 23u), x22);
        result = field_mul(field_square_repeated(result, 6u), x2);
        return field_square_repeated(result, 2u);
    }

    inline bool field_is_quadratic_residue(U256 value) {
        if (u256_is_zero(value)) {
            return true;
        }
        U256 candidate = field_sqrt_candidate(value);
        return u256_equal(field_square(candidate), value);
    }

    inline Point point_infinity() {
        Point point;
        point.x = u256_zero();
        point.y = u256_zero();
        point.z = u256_zero();
        point.infinity = true;
        return point;
    }

    inline Point point_from_affine(U256 x, U256 y) {
        Point point;
        point.x = x;
        point.y = y;
        point.z = u256_one();
        point.infinity = false;
        return point;
    }

    inline Point point_double(Point point) {
        if (point.infinity || u256_is_zero(point.y)) {
            return point_infinity();
        }

        U256 xSquared = field_square(point.x);
        U256 ySquared = field_square(point.y);
        U256 yFourth = field_square(ySquared);
        U256 yFourthTimesEight = field_double(field_double(field_double(yFourth)));
        U256 xPlusYSquared = field_add(point.x, ySquared);
        U256 delta = field_double(field_sub(field_sub(field_square(xPlusYSquared), xSquared), yFourth));
        U256 threeX = field_add(field_double(xSquared), xSquared);
        U256 resultX = field_sub(field_square(threeX), field_double(delta));
        U256 resultY = field_sub(field_mul(threeX, field_sub(delta, resultX)), yFourthTimesEight);
        U256 resultZ = field_double(field_mul(point.y, point.z));

        Point result;
        result.x = resultX;
        result.y = resultY;
        result.z = resultZ;
        result.infinity = false;
        return result;
    }

    inline Point point_add_affine(Point point, U256 otherX, U256 otherY) {
        if (point.infinity) {
            return point_from_affine(otherX, otherY);
        }

        U256 zSquared = field_square(point.z);
        U256 otherXAdjusted = field_mul(otherX, zSquared);
        U256 otherYAdjusted = field_mul(otherY, field_mul(zSquared, point.z));
        U256 xDifference = field_sub(otherXAdjusted, point.x);
        U256 yDifference = field_sub(otherYAdjusted, point.y);

        if (u256_is_zero(xDifference)) {
            return u256_is_zero(yDifference) ? point_double(point) : point_infinity();
        }

        U256 xDifferenceSquared = field_square(xDifference);
        U256 xDifferenceCubed = field_mul(xDifference, xDifferenceSquared);
        U256 xProduct = field_mul(point.x, xDifferenceSquared);

        U256 resultX = field_sub(field_sub(field_square(yDifference), xDifferenceCubed), field_double(xProduct));
        U256 resultY = field_sub(field_mul(yDifference, field_sub(xProduct, resultX)), field_mul(point.y, xDifferenceCubed));
        U256 resultZ = field_mul(point.z, xDifference);

        Point result;
        result.x = resultX;
        result.y = resultY;
        result.z = resultZ;
        result.infinity = false;
        return result;
    }

    inline Point point_add(Point first, Point second) {
        if (first.infinity) {
            return second;
        }
        if (second.infinity) {
            return first;
        }

        U256 firstZSquared = field_square(first.z);
        U256 secondZSquared = field_square(second.z);
        U256 firstXAdjusted = field_mul(first.x, secondZSquared);
        U256 secondXAdjusted = field_mul(second.x, firstZSquared);
        U256 firstZCubed = field_mul(firstZSquared, first.z);
        U256 secondZCubed = field_mul(secondZSquared, second.z);
        U256 firstYAdjusted = field_mul(first.y, secondZCubed);
        U256 secondYAdjusted = field_mul(second.y, firstZCubed);

        if (u256_equal(firstXAdjusted, secondXAdjusted)) {
            if (!u256_equal(firstYAdjusted, secondYAdjusted)) {
                return point_infinity();
            }
            return point_double(first);
        }

        U256 xDifference = field_sub(secondXAdjusted, firstXAdjusted);
        U256 xDifferenceSquared = field_square(field_double(xDifference));
        U256 xDifferenceCubed = field_mul(xDifference, xDifferenceSquared);
        U256 yDifference = field_double(field_sub(secondYAdjusted, firstYAdjusted));
        U256 firstProduct = field_mul(firstXAdjusted, xDifferenceSquared);
        U256 resultX = field_sub(field_sub(field_square(yDifference), xDifferenceCubed), field_double(firstProduct));
        U256 resultY = field_sub(
            field_mul(yDifference, field_sub(firstProduct, resultX)),
            field_double(field_mul(firstYAdjusted, xDifferenceCubed))
        );
        U256 resultZ = field_mul(
            field_sub(field_sub(field_square(field_add(first.z, second.z)), firstZSquared), secondZSquared),
            xDifference
        );

        Point result;
        result.x = resultX;
        result.y = resultY;
        result.z = resultZ;
        result.infinity = false;
        return result;
    }

    inline U256 read_u256(device const uint *records, uint base) {
        U256 value;
        for (uint i = 0; i < 8; i++) {
            value.v[i] = records[base + i];
        }
        return value;
    }

    inline U256 read_table_u256(device const uint *tables, uint tableBase, uint tableIndex, uint coordinateOffset) {
        U256 value;
        uint base = tableBase + (tableIndex * 16u) + coordinateOffset;
        for (uint i = 0; i < 8; i++) {
            value.v[i] = tables[base + i];
        }
        return value;
    }

    inline int read_wnaf_digit(
        device const char *digits,
        uint recordIndex,
        uint component,
        uint index,
        uint recordCount
    ) {
        uint offset = ((component * 130u + index) * recordCount) + recordIndex;
        return int(digits[offset]);
    }

    inline Point add_wnaf_digit(Point result, device const uint *tables, uint component, int digit) {
        if (digit == 0) {
            return result;
        }
        int magnitude = digit < 0 ? -digit : digit;
        uint tableIndex = uint(magnitude >> 1);
        uint tableBase = component * 512u;
        U256 x = read_table_u256(tables, tableBase, tableIndex, 0u);
        U256 y = read_table_u256(tables, tableBase, tableIndex, 8u);
        if (digit < 0) {
            y = field_negate(y);
        }
        return point_add_affine(result, x, y);
    }

    inline Point scalar_mul_wnaf(
        device const uint *tables,
        device const char *digits,
        uint recordIndex,
        uint recordCount
    ) {
        Point result = point_infinity();
        for (int index = 129; index >= 0; index--) {
            result = point_double(result);
            uint digitIndex = uint(index);
            result = add_wnaf_digit(result, tables, 0u, read_wnaf_digit(digits, recordIndex, 0u, digitIndex, recordCount));
            result = add_wnaf_digit(result, tables, 1u, read_wnaf_digit(digits, recordIndex, 1u, digitIndex, recordCount));
            result = add_wnaf_digit(result, tables, 2u, read_wnaf_digit(digits, recordIndex, 2u, digitIndex, recordCount));
            result = add_wnaf_digit(result, tables, 3u, read_wnaf_digit(digits, recordIndex, 3u, digitIndex, recordCount));
        }
        return result;
    }

    inline U256 read_varying_table_u256(
        device const uint *tables,
        uint recordIndex,
        uint recordCount,
        uint component,
        uint tableIndex,
        uint coordinateOffset
    ) {
        U256 value;
        uint componentBase = (component - 2u) * 32u;
        uint slotBase = componentBase + tableIndex * 16u + coordinateOffset;
        for (uint limb = 0u; limb < 8u; limb++) {
            uint slot = slotBase + limb;
            value.v[limb] = tables[slot * recordCount + recordIndex];
        }
        return value;
    }

    inline Point add_varying_wnaf_digit(
        Point result,
        device const uint *sharedGeneratorTables,
        device const uint *varyingVerificationKeyTables,
        uint recordIndex,
        uint recordCount,
        uint component,
        int digit
    ) {
        if (digit == 0) {
            return result;
        }
        int magnitude = digit < 0 ? -digit : digit;
        uint tableIndex = uint(magnitude >> 1);
        U256 x;
        U256 y;
        if (component < 2u) {
            uint tableBase = component * 512u;
            x = read_table_u256(sharedGeneratorTables, tableBase, tableIndex, 0u);
            y = read_table_u256(sharedGeneratorTables, tableBase, tableIndex, 8u);
        } else {
            // Key components use width-3 WNAF, so magnitude <= 3 and tableIndex <= 1.
            x = read_varying_table_u256(
                varyingVerificationKeyTables,
                recordIndex,
                recordCount,
                component,
                tableIndex,
                0u
            );
            y = read_varying_table_u256(
                varyingVerificationKeyTables,
                recordIndex,
                recordCount,
                component,
                tableIndex,
                8u
            );
        }
        if (digit < 0) {
            y = field_negate(y);
        }
        return point_add_affine(result, x, y);
    }

    inline Point scalar_mul_wnaf_varying_key(
        device const uint *sharedGeneratorTables,
        device const uint *varyingVerificationKeyTables,
        device const char *digits,
        uint recordIndex,
        uint recordCount
    ) {
        Point result = point_infinity();
        for (int index = 129; index >= 0; index--) {
            result = point_double(result);
            uint digitIndex = uint(index);
            for (uint component = 0u; component < 4u; component++) {
                result = add_varying_wnaf_digit(
                    result,
                    sharedGeneratorTables,
                    varyingVerificationKeyTables,
                    recordIndex,
                    recordCount,
                    component,
                    read_wnaf_digit(
                        digits,
                        recordIndex,
                        component,
                        digitIndex,
                        recordCount
                    )
                );
            }
        }
        return result;
    }

    inline bool verify_schnorr_record(
        device const uint *records,
        device const uint *tables,
        device const char *digits,
        uint recordIndex,
        uint base,
        uint recordCount
    ) {
        U256 signatureX = read_u256(records, base);

        Point candidate = scalar_mul_wnaf(tables, digits, recordIndex, recordCount);
        if (candidate.infinity) {
            return false;
        }
        U256 zSquared = field_square(candidate.z);
        U256 expectedX = field_mul(signatureX, zSquared);
        if (!u256_equal(candidate.x, expectedX)) {
            return false;
        }
        U256 jacobiCandidate = field_mul(candidate.y, candidate.z);
        return field_is_quadratic_residue(jacobiCandidate);
    }

    inline bool verify_schnorr_varying_key_record(
        device const uint *records,
        device const uint *sharedGeneratorTables,
        device const uint *varyingVerificationKeyTables,
        device const char *digits,
        uint recordIndex,
        uint base,
        uint recordCount
    ) {
        U256 signatureX = read_u256(records, base);
        Point candidate = scalar_mul_wnaf_varying_key(
            sharedGeneratorTables,
            varyingVerificationKeyTables,
            digits,
            recordIndex,
            recordCount
        );
        if (candidate.infinity) {
            return false;
        }
        U256 zSquared = field_square(candidate.z);
        U256 expectedX = field_mul(signatureX, zSquared);
        if (!u256_equal(candidate.x, expectedX)) {
            return false;
        }
        U256 jacobiCandidate = field_mul(candidate.y, candidate.z);
        return field_is_quadratic_residue(jacobiCandidate);
    }

    kernel void opal_schnorr_verify_core(
        device const uint *records [[buffer(0)]],
        device uint *output [[buffer(1)]],
        constant uint &recordCount [[buffer(2)]],
        device const uint *tables [[buffer(3)]],
        device const char *digits [[buffer(4)]],
        uint id [[thread_position_in_grid]]
    ) {
        if (id >= recordCount) {
            return;
        }
        uint base = id * 8u;
        output[id] = verify_schnorr_record(
            records,
            tables,
            digits,
            id,
            base,
            recordCount
        ) ? 1u : 0u;
    }

    kernel void opal_schnorr_verify_varying_key(
        device const uint *records [[buffer(0)]],
        device uint *output [[buffer(1)]],
        constant uint &recordCount [[buffer(2)]],
        device const uint *sharedGeneratorTables [[buffer(3)]],
        device const uint *varyingVerificationKeyTables [[buffer(4)]],
        device const char *digits [[buffer(5)]],
        uint id [[thread_position_in_grid]]
    ) {
        if (id >= recordCount) {
            return;
        }
        uint base = id * 8u;
        output[id] = verify_schnorr_varying_key_record(
            records,
            sharedGeneratorTables,
            varyingVerificationKeyTables,
            digits,
            id,
            base,
            recordCount
        ) ? 1u : 0u;
    }

    kernel void opal_field_validation(
        device const uint *records [[buffer(0)]],
        device uint *output [[buffer(1)]],
        constant uint &caseCount [[buffer(2)]],
        uint id [[thread_position_in_grid]]
    ) {
        if (id >= caseCount) {
            return;
        }

        uint inputBase = id * 16u;
        U256 left = read_u256(records, inputBase);
        U256 right = read_u256(records, inputBase + 8u);
        U256 product = field_mul(left, right);
        U256 square = field_square(left);
        uint outputBase = id * 17u;
        for (uint limb = 0u; limb < 8u; limb++) {
            output[outputBase + limb] = product.v[limb];
            output[outputBase + 8u + limb] = square.v[limb];
        }
        output[outputBase + 16u] = field_is_quadratic_residue(left) ? 1u : 0u;
    }
    """
}
#endif
