// RipeMessageDigest160Model+.swift

import Foundation

extension RipeMessageDigest160Model {
    static func hash(_ data: Data) -> Data {
        var ripeMessageDigest = Self()
        ripeMessageDigest.update(data: data)
        return ripeMessageDigest.finalize()
    }
}

// MARK: - RIPEMD-160 Hashing
extension RipeMessageDigest160Model {
    mutating func update(data: Data) {
        withUnsafeTemporaryAllocation(of: UInt32.self, capacity: 16) { words in
            words.initialize(repeating: 0)
            var currentPosition = data.startIndex
            var remainingLength = data.count

            if messageBuffer.count > 0 && messageBuffer.count + remainingLength >= 64 {
                let chunkSize = 64 - messageBuffer.count
                messageBuffer.append(data[..<chunkSize])
                guard let baseAddress = words.baseAddress else { return }
                let wordBytes = UnsafeMutableRawBufferPointer(start: baseAddress, count: 64)
                _ = messageBuffer.copyBytes(to: wordBytes)
                compress(baseAddress)
                currentPosition += chunkSize
                remainingLength -= chunkSize
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
