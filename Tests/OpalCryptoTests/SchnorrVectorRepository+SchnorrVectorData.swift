// SchnorrVectorRepository+SchnorrVectorData.swift

import Foundation

extension SchnorrVectorRepository {
    struct SchnorrVectorData: Sendable {
        let index: Int
        let secretKeyHex: String?
        let publicKeyHex: String
        let messageHex: String
        let signatureHex: String
        let isVerificationExpected: Bool
        let comment: String?

        var secretKey32: Data? { get throws { try Self.decodeHex(secretKeyHex, expectedCount: 32, field: "secret key", index: index) } }
        var publicKey: Data { get throws { try Self.decodeHex(publicKeyHex, expectedCount: 33, field: "public key", index: index)! } }
        var message32: Data { get throws { try Self.decodeHex(messageHex, expectedCount: 32, field: "message", index: index)! } }
        var signature64: Data { get throws { try Self.decodeHex(signatureHex, expectedCount: 64, field: "signature", index: index)! } }

        private static func decodeHex(
            _ value: String?,
            expectedCount: Int,
            field: String,
            index: Int
        ) throws -> Data? {
            guard let value else { return nil }
            let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !normalized.isEmpty else { throw Error.emptyHexField(field: field, index: index) }
            guard normalized.count.isMultiple(of: 2) else { throw Error.oddHexLength(field: field, index: index, count: normalized.count) }

            var output = Data()
            output.reserveCapacity(normalized.count / 2)
            var cursor = normalized.startIndex
            var byteOffset = 0
            while cursor < normalized.endIndex {
                let next = normalized.index(cursor, offsetBy: 2)
                let pair = normalized[cursor..<next]
                guard let byte = UInt8(pair, radix: 16) else {
                    throw Error.invalidHexPair(field: field, index: index, byteOffset: byteOffset, pair: String(pair))
                }
                output.append(byte)
                cursor = next
                byteOffset += 1
            }
            guard output.count == expectedCount else {
                throw Error.invalidByteCount(field: field, index: index, expected: expectedCount, actual: output.count)
            }
            return output
        }
    }
}
