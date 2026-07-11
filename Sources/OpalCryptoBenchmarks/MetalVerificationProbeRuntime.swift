// MetalVerificationProbeRuntime.swift

#if canImport(Metal)
import Metal

final class MetalVerificationProbeRuntime: @unchecked Sendable {
    static let shared = try! MetalVerificationProbeRuntime()

    private let device: MTLDevice
    private let commandQueue: MTLCommandQueue
    private let pipelineState: MTLComputePipelineState

    private init() throws {
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
        guard let function = library.makeFunction(name: "opal_verification_probe") else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }
        pipelineState = try device.makeComputePipelineState(function: function)
    }

    func run(
        records: [OpalCryptoBenchmarks.MetalVerificationProbeRecord]
    ) throws -> Int {
        guard !records.isEmpty else { return 0 }

        let recordByteCount = records.count
            * MemoryLayout<OpalCryptoBenchmarks.MetalVerificationProbeRecord>.stride
        guard let inputBuffer = device.makeBuffer(
            bytes: records,
            length: recordByteCount,
            options: .storageModeShared
        ),
            let outputBuffer = device.makeBuffer(
                length: records.count * MemoryLayout<UInt32>.stride,
                options: .storageModeShared
            )
        else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }

        var recordCount = UInt32(records.count)
        guard let countBuffer = device.makeBuffer(
            bytes: &recordCount,
            length: MemoryLayout<UInt32>.stride,
            options: .storageModeShared
        ),
            let commandBuffer = commandQueue.makeCommandBuffer(),
            let encoder = commandBuffer.makeComputeCommandEncoder()
        else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }

        encoder.setComputePipelineState(pipelineState)
        encoder.setBuffer(inputBuffer, offset: 0, index: 0)
        encoder.setBuffer(outputBuffer, offset: 0, index: 1)
        encoder.setBuffer(countBuffer, offset: 0, index: 2)

        let threadCount = MTLSize(width: records.count, height: 1, depth: 1)
        let threadsPerThreadgroup = MTLSize(
            width: min(records.count, pipelineState.maxTotalThreadsPerThreadgroup),
            height: 1,
            depth: 1
        )
        encoder.dispatchThreads(
            threadCount,
            threadsPerThreadgroup: threadsPerThreadgroup
        )
        encoder.endEncoding()
        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()

        if commandBuffer.status == .error {
            let message = commandBuffer.error?.localizedDescription ?? "unknown error"
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.commandBufferFailed(message)
        }

        // SAFETY: outputBuffer owns records.count initialized UInt32 slots for
        // the duration of this synchronous readback, and every index below is
        // bounded by records.indices.
        let output = outputBuffer.contents().bindMemory(
            to: UInt32.self,
            capacity: records.count
        )
        var checksum = 0
        for index in records.indices {
            let expected = Self.expectedProbeOutput(for: records[index])
            guard output[index] == expected else {
                throw OpalCryptoBenchmarks.MetalVerificationProbeError.invalidResult(index: index)
            }
            checksum ^= Int(output[index])
        }
        return checksum
    }

    private static func expectedProbeOutput(
        for record: OpalCryptoBenchmarks.MetalVerificationProbeRecord
    ) -> UInt32 {
        (record.expected & 1) ^ record.tag ^ 0x9e37_79b9
    }

    private static let kernelSource = """
    #include <metal_stdlib>
    using namespace metal;

    struct VerificationProbeRecord {
        uint expected;
        uint tag;
    };

    kernel void opal_verification_probe(
        device const VerificationProbeRecord *records [[buffer(0)]],
        device uint *output [[buffer(1)]],
        constant uint &recordCount [[buffer(2)]],
        uint id [[thread_position_in_grid]]
    ) {
        if (id >= recordCount) {
            return;
        }
        VerificationProbeRecord record = records[id];
        output[id] = (record.expected & 1u) ^ record.tag ^ 0x9e3779b9u;
    }
    """
}
#endif
