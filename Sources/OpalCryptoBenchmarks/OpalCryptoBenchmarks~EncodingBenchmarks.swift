// OpalCryptoBenchmarks~EncodingBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func runEncodingBenchmarks(context: BenchmarkContext) throws -> Int {
        var checksum = 0

        checksum ^= runSyncBenchmark(name: "Base58 encode", iterations: 500) {
            let encoded = OpalCrypto.Encoding.encodeBase58(context.basePayload)
            return encoded.count ^ encoded.utf8.reduce(0) { $0 ^ Int($1) }
        }

        checksum ^= runSyncBenchmark(name: "Base58 decode", iterations: 500) {
            let decoded = OpalCrypto.Encoding.decodeBase58(context.base58EncodedPayload)!
            return decoded.count ^ Int(decoded[0])
        }

        checksum ^= try runSyncBenchmark(name: "Base32 encode", iterations: 500) {
            let encoded = try OpalCrypto.Encoding.encodeBase32(
                context.basePayload,
                interpretedAsFiveBitValues: false
            )
            return encoded.count ^ encoded.utf8.reduce(0) { $0 ^ Int($1) }
        }

        checksum ^= try runSyncBenchmark(name: "Base32 decode", iterations: 500) {
            let decoded = try OpalCrypto.Encoding.decodeBase32(
                context.base32EncodedPayload,
                interpretedAsFiveBitValues: false
            )
            return decoded.count ^ Int(decoded[0])
        }

        return checksum
    }
}
