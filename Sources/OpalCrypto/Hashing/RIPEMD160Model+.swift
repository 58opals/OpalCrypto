// RIPEMD160Model+.swift

import Foundation

extension RIPEMD160Model {
    static func hash(_ data: Data) -> Data {
        var ripeMessageDigest = Self()
        ripeMessageDigest.update(data: data)
        return ripeMessageDigest.finalize()
    }
}

// MARK: - RIPEMD-160 Hashing
extension RIPEMD160Model {
    mutating func update(data: Data) {
        // SAFETY: The temporary allocation owns 16 initialized UInt32 words for
        // this closure. Each raw projection spans exactly those 64 bytes, and
        // every copied block is exactly 64 bytes. Supported Apple targets are
        // little-endian, matching RIPEMD-160's message-word representation.
        withUnsafeTemporaryAllocation(of: UInt32.self, capacity: 16) { words in
            words.initialize(repeating: 0)
            var currentPosition = data.startIndex
            var remainingLength = data.count

            if messageBuffer.count > 0 {
                let chunkSize = min(64 - messageBuffer.count, remainingLength)
                messageBuffer.append(data[currentPosition..<currentPosition + chunkSize])
                currentPosition += chunkSize
                remainingLength -= chunkSize

                guard messageBuffer.count == 64 else {
                    processedBytesCount += Int64(data.count)
                    return
                }

                guard let baseAddress = words.baseAddress else { return }
                let wordBytes = UnsafeMutableRawBufferPointer(start: baseAddress, count: 64)
                _ = messageBuffer.copyBytes(to: wordBytes)
                compress(baseAddress)
                messageBuffer.removeAll(keepingCapacity: true)
            }

            while remainingLength >= 64 {
                guard let baseAddress = words.baseAddress else { return }
                let wordBytes = UnsafeMutableRawBufferPointer(start: baseAddress, count: 64)
                _ = data[currentPosition..<currentPosition + 64].copyBytes(to: wordBytes)
                compress(baseAddress)
                currentPosition += 64
                remainingLength -= 64
            }

            messageBuffer = data[currentPosition...]
            processedBytesCount += Int64(data.count)
        }
    }

    mutating func finalize() -> Data {
        // SAFETY: The 16-word buffer is initialized before any raw projection,
        // remains alive through compression, and has exactly 64 writable bytes.
        // messageBuffer is at most one block, unwritten padding stays zero, and
        // result.withUnsafeBytes is copied into Data before its array expires.
        // Supported Apple targets are little-endian, matching RIPEMD-160's
        // message-word and digest-byte representation.
        withUnsafeTemporaryAllocation(of: UInt32.self, capacity: 16) { words in
            words.initialize(repeating: 0)
            messageBuffer.append(0x80)
            guard let baseAddress = words.baseAddress else { return Data() }
            let wordBytes = UnsafeMutableRawBufferPointer(start: baseAddress, count: 64)
            _ = messageBuffer.copyBytes(to: wordBytes)

            if (processedBytesCount & 63) > 55 {
                compress(baseAddress)
                words.update(repeating: 0)
            }

            let lowerWord = UInt32(truncatingIfNeeded: processedBytesCount)
            let upperWord = UInt32(UInt64(processedBytesCount) >> 32)
            words[14] = lowerWord << 3
            words[15] = (lowerWord >> 29) | (upperWord << 3)
            compress(baseAddress)

            messageBuffer = Data()
            let result = [hashState.0, hashState.1, hashState.2, hashState.3, hashState.4]
            return result.withUnsafeBytes { Data($0) }
        }
    }
}
