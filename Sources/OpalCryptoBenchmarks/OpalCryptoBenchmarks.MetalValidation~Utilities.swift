// OpalCryptoBenchmarks.MetalValidation~Utilities.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks.MetalValidation {
    static func checksum(_ results: [UInt32]) -> Int {
        var checksum = 0
        for (index, result) in results.enumerated() {
            checksum ^= Int(result) &+ index
        }
        return checksum
    }

    static func decodeHex(_ hex: String) throws -> Data {
        guard hex.count.isMultiple(of: 2) else {
            throw Error.invalidHex
        }
        var data = Data()
        data.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
                throw Error.invalidHex
            }
            data.append(byte)
            index = nextIndex
        }
        return data
    }
}
