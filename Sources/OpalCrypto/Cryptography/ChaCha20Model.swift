// ChaCha20Model.swift

import Foundation

enum ChaCha20Model {
    static func crypt(
        _ input: Data,
        key: Data,
        nonce: Data,
        initialCounter: UInt32 = 0
    ) -> Data {
        precondition(key.count == 32)
        precondition(nonce.count == 12)
        var output = [UInt8](repeating: 0, count: input.count)
        let inputBytes = [UInt8](input)
        let keyBytes = [UInt8](key)
        let nonceBytes = [UInt8](nonce)

        for blockOffset in stride(from: 0, to: inputBytes.count, by: 64) {
            let counter = initialCounter
                &+ UInt32(blockOffset / 64)
            let block = keyStreamBlock(
                key: keyBytes,
                nonce: nonceBytes,
                counter: counter
            )
            let blockByteCount = min(64, inputBytes.count - blockOffset)
            for index in 0 ..< blockByteCount {
                output[blockOffset + index] = inputBytes[blockOffset + index]
                    ^ block[index]
            }
        }
        return Data(output)
    }

    static func keyStreamBlock(
        key: [UInt8],
        nonce: [UInt8],
        counter: UInt32
    ) -> [UInt8] {
        var state: [UInt32] = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            word(key, at: 0), word(key, at: 4),
            word(key, at: 8), word(key, at: 12),
            word(key, at: 16), word(key, at: 20),
            word(key, at: 24), word(key, at: 28),
            counter,
            word(nonce, at: 0), word(nonce, at: 4), word(nonce, at: 8)
        ]
        let initialState = state
        for _ in 0 ..< 10 {
            quarterRound(&state, 0, 4, 8, 12)
            quarterRound(&state, 1, 5, 9, 13)
            quarterRound(&state, 2, 6, 10, 14)
            quarterRound(&state, 3, 7, 11, 15)
            quarterRound(&state, 0, 5, 10, 15)
            quarterRound(&state, 1, 6, 11, 12)
            quarterRound(&state, 2, 7, 8, 13)
            quarterRound(&state, 3, 4, 9, 14)
        }
        var block: [UInt8] = []
        block.reserveCapacity(64)
        for index in state.indices {
            let value = state[index] &+ initialState[index]
            block.append(UInt8(truncatingIfNeeded: value))
            block.append(UInt8(truncatingIfNeeded: value >> 8))
            block.append(UInt8(truncatingIfNeeded: value >> 16))
            block.append(UInt8(truncatingIfNeeded: value >> 24))
        }
        return block
    }

    private static func quarterRound(
        _ state: inout [UInt32],
        _ a: Int,
        _ b: Int,
        _ c: Int,
        _ d: Int
    ) {
        state[a] &+= state[b]
        state[d] = (state[d] ^ state[a]).rotatedLeft(by: 16)
        state[c] &+= state[d]
        state[b] = (state[b] ^ state[c]).rotatedLeft(by: 12)
        state[a] &+= state[b]
        state[d] = (state[d] ^ state[a]).rotatedLeft(by: 8)
        state[c] &+= state[d]
        state[b] = (state[b] ^ state[c]).rotatedLeft(by: 7)
    }

    private static func word(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }
}

private extension UInt32 {
    func rotatedLeft(by count: UInt32) -> UInt32 {
        (self << count) | (self >> (32 - count))
    }
}
