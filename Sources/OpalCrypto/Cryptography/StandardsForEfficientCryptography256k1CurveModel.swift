//  StandardsForEfficientCryptography256k1CurveModel.swift

import Foundation

public enum StandardsForEfficientCryptography256k1CurveModel {
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
            let rValue = Data(raw64ByteSignatureData.prefix(32))
            let sValue = Data(raw64ByteSignatureData.suffix(32))
            try self.init(r: rValue, s: sValue)
        }
        
        public init(r: Data, s: Data) throws {
            guard r.count == 32, s.count == 32 else {
                throw Error.invalidSignatureLength(actual: r.count + s.count)
            }
            _ = try Self.makeSignatureScalar(from: r)
            _ = try Self.makeSignatureScalar(from: s)
            self.r = Data(r)
            self.s = Data(s)
        }
        
        public func encodeDistinguishedEncodingRules() throws -> Data {
            try StandardsForEfficientCryptography256k1CurveModel.DistinguishedEncodingRulesModel.encodeSignature(r: r, s: s)
        }
        
        public init(distinguishedEncodingRulesEncoded: Data) throws {
            let signatureValues = try StandardsForEfficientCryptography256k1CurveModel.DistinguishedEncodingRulesModel.decodeSignature(
                distinguishedEncodingRulesEncoded
            )
            try self.init(r: signatureValues.r, s: signatureValues.s)
        }
        
        public func normalizeLowS() -> Signature {
            guard let signatureSScalar = try? Self.makeSignatureScalar(from: s) else {
                return self
            }
            guard signatureSScalar.compare(to: StandardsForEfficientCryptography256k1CurveModel.halfOrderScalar) == .orderedDescending else {
                return self
            }
            let normalizedScalar = signatureSScalar.negateModN()
            return (try? Signature(r: r, s: normalizedScalar.data32Bytes)) ?? self
        }
        
        public var isLowS: Bool {
            guard let signatureSScalar = try? Self.makeSignatureScalar(from: s) else {
                return false
            }
            return signatureSScalar.compare(to: StandardsForEfficientCryptography256k1CurveModel.halfOrderScalar) != .orderedDescending
        }
        
        private static func makeSignatureScalar(from data: Data) throws -> ScalarModel {
            do {
                return try ScalarModel(data32: data, requireNonZero: true)
            } catch ScalarModel.Error.zeroNotAllowed {
                throw Error.signatureComponentZero
            } catch {
                throw Error.invalidSignatureScalar
            }
        }
    }
    
    static let halfOrderScalar = ScalarModel(
        unchecked: Unsigned256BitIntegerModel(
            limbs: [
                0xdfe92f46681b20a0,
                0x5d576e7357a4501d,
                0xffffffffffffffff,
                0x7fffffffffffffff
            ]
        )
    )
}
