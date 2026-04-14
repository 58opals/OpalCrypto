// OpalCrypto.Numeric+UInt512.swift

import Foundation

extension OpalCrypto.Numeric {
    public struct UInt512: Sendable, Equatable {
        internal let rawValue: Unsigned512BitIntegerModel

        public init(data64Bytes: Data) throws {
            do {
                self.rawValue = try Unsigned512BitIntegerModel(data64Bytes: data64Bytes)
            } catch {
                throw Error.invalidDataLength(expected: 64, actual: data64Bytes.count)
            }
        }

        public var bytes64: Data {
            rawValue.data64Bytes
        }

        public var isZero: Bool {
            rawValue.isZero
        }

        internal init(rawValue: Unsigned512BitIntegerModel) {
            self.rawValue = rawValue
        }
    }
}
