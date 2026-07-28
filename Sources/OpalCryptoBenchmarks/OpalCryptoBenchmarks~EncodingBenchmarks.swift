// OpalCryptoBenchmarks~EncodingBenchmarks.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    static func encodingBenchmarks() -> [BenchmarkCase] {
        [
            BenchmarkCase(
                name: "Base58 encode",
                iterations: 500,
                suites: [.smoke],
                operation: .sync { context in
                    let encoded = OpalCrypto.Encoding.encodeBase58(context.basePayload)
                    return encoded.count ^ encoded.utf8.reduce(0) { $0 ^ Int($1) }
                }
            ),
            BenchmarkCase(
                name: "Base58 decode",
                iterations: 500,
                suites: [],
                operation: .sync { context in
                    let decoded = OpalCrypto.Encoding.decodeBase58(
                        context.base58EncodedPayload,
                        maximumDecodedByteCount: context.basePayload.count
                    )!
                    return decoded.count ^ Int(decoded[0])
                }
            ),
            BenchmarkCase(
                name: "Base32 encode",
                iterations: 500,
                suites: [],
                operation: .sync { context in
                    let encoded = try OpalCrypto.Encoding.encodeBase32Bytes(context.basePayload)
                    return encoded.count ^ encoded.utf8.reduce(0) { $0 ^ Int($1) }
                }
            ),
            BenchmarkCase(
                name: "Base32 decode",
                iterations: 500,
                suites: [],
                operation: .sync { context in
                    let decoded = try OpalCrypto.Encoding.decodeBase32Bytes(
                        context.base32EncodedPayload,
                        maximumDecodedByteCount: context.basePayload.count
                    )
                    return decoded.count ^ Int(decoded[0])
                }
            )
        ]
    }
}
