// SchnorrSignatureModel+Signature.swift

import Foundation

extension SchnorrSignatureModel {
    internal struct Signature: Sendable, Equatable {
        internal let r: Data
        internal let s: Data
        
        internal var raw64ByteSignatureData: Data {
            r + s
        }
        
        internal init(raw64ByteSignatureData: Data) throws {
            guard raw64ByteSignatureData.count == 64 else {
                throw Error.invalidSignatureLength(actual: raw64ByteSignatureData.count)
            }
            r = Data(raw64ByteSignatureData.prefix(32))
            s = Data(raw64ByteSignatureData.suffix(32))
        }
        
        internal init(r: Data, s: Data) throws {
            guard r.count == 32, s.count == 32 else {
                throw Error.invalidSignatureLength(actual: r.count + s.count)
            }
            self.r = Data(r)
            self.s = Data(s)
        }
    }
}
