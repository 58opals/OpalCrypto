// SchnorrSignatureModel.swift

import Foundation

public enum SchnorrSignatureModel {
    public struct Signature: Sendable, Equatable {
        public let r: Data
        public let s: Data
        
        public var raw64ByteSignatureData: Data {
            r + s
        }
        
        public init(raw64ByteSignatureData: Data) throws {
            guard raw64ByteSignatureData.count == 64 else {
                throw Error.invalidSignatureLength(actual: raw64ByteSignatureData.count)
            }
            r = Data(raw64ByteSignatureData.prefix(32))
            s = Data(raw64ByteSignatureData.suffix(32))
        }
        
        public init(r: Data, s: Data) throws {
            guard r.count == 32, s.count == 32 else {
                throw Error.invalidSignatureLength(actual: r.count + s.count)
            }
            self.r = Data(r)
            self.s = Data(s)
        }
    }
}
