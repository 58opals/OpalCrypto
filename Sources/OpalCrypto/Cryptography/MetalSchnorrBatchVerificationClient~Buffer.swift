// MetalSchnorrBatchVerificationClient~Buffer.swift

#if canImport(Metal) && canImport(OpalCryptoMetal)
import Metal

extension MetalSchnorrBatchVerificationClient {
    func ensureBuffer(
        _ current: (any MTLBuffer)?,
        minimumByteCount: Int
    ) throws -> any MTLBuffer {
        if let current, current.length >= minimumByteCount {
            return current
        }
        guard minimumByteCount > 0, let device else {
            throw MetalSchnorrBatchVerificationError.invalidInput
        }
        let byteCount = try Self.replacementBufferByteCount(
            minimumByteCount: minimumByteCount,
            allocatedBufferByteCount: allocatedBufferByteCount
        )
        guard let replacement = device.makeBuffer(
            length: byteCount,
            options: .storageModeShared
        ) else {
            throw MetalSchnorrBatchVerificationError.bufferAllocationFailed
        }
        return replacement
    }

    var allocatedBufferByteCount: Int {
        [
            countBuffer,
            inputBuffer,
            digitBuffer,
            outputBuffer,
            cachedKeyTableBuffer,
            sharedGeneratorTableBuffer,
            varyingKeyTableBuffer
        ].compactMap { $0?.length }.reduce(0, +)
    }

    func cacheCachedKeyTable(
        identifier: Data,
        words: [UInt32]
    ) throws -> any MTLBuffer {
        if let cachedKeyTableBuffer,
           cachedKeyTableIdentifier == identifier {
            return cachedKeyTableBuffer
        }
        let byteCount = words.count * MemoryLayout<UInt32>.stride
        let buffer = try ensureBuffer(
            cachedKeyTableBuffer,
            minimumByteCount: byteCount
        )
        copy(words, byteCount: byteCount, to: buffer)
        cachedKeyTableBuffer = buffer
        cachedKeyTableIdentifier = identifier
        return buffer
    }

    func cacheSharedGeneratorTable(
        words: [UInt32]
    ) throws -> any MTLBuffer {
        if let sharedGeneratorTableBuffer,
           let cachedSharedGeneratorTableWords {
            guard cachedSharedGeneratorTableWords == words else {
                throw MetalSchnorrBatchVerificationError.invalidInput
            }
            return sharedGeneratorTableBuffer
        }
        let byteCount = words.count * MemoryLayout<UInt32>.stride
        let buffer = try ensureBuffer(
            sharedGeneratorTableBuffer,
            minimumByteCount: byteCount
        )
        copy(words, byteCount: byteCount, to: buffer)
        sharedGeneratorTableBuffer = buffer
        cachedSharedGeneratorTableWords = words
        return buffer
    }

    func copy<Element>(
        _ values: [Element],
        byteCount: Int,
        to buffer: any MTLBuffer
    ) {
        precondition(
            byteCount >= 0
                && byteCount <= values.count * MemoryLayout<Element>.stride
                && byteCount <= buffer.length
        )
        values.withUnsafeBufferPointer { source in
            guard let baseAddress = source.baseAddress else { return }
            // SAFETY: The precondition bounds byteCount to both the contiguous
            // source array and the live shared Metal buffer.
            buffer.contents().copyMemory(
                from: baseAddress,
                byteCount: byteCount
            )
        }
    }
}
#endif
