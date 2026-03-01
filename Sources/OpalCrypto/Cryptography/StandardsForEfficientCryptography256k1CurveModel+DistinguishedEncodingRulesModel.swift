// StandardsForEfficientCryptography256k1CurveModel+DistinguishedEncodingRulesModel.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel {
    enum DistinguishedEncodingRulesModel {
        static func encodeSignature(r: Data, s: Data) throws -> Data {
            guard r.count == 32, s.count == 32 else {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.invalidSignatureLength(actual: r.count + s.count)
            }
            let rEncoded = encodeIntegerBytes(r)
            let sEncoded = encodeIntegerBytes(s)
            var sequence = Data()
            sequence.append(0x02)
            sequence.append(try DistinguishedEncodingRulesLengthModel.encode(rEncoded.count))
            sequence.append(rEncoded)
            sequence.append(0x02)
            sequence.append(try DistinguishedEncodingRulesLengthModel.encode(sEncoded.count))
            sequence.append(sEncoded)
            var result = Data()
            result.append(0x30)
            result.append(try DistinguishedEncodingRulesLengthModel.encode(sequence.count))
            result.append(sequence)
            return result
        }
        
        static func decodeSignature(_ distinguishedEncodingRulesEncoded: Data) throws -> (r: Data, s: Data) {
            guard !distinguishedEncodingRulesEncoded.isEmpty else {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derMalformed
            }
            var index = 0
            guard distinguishedEncodingRulesEncoded[index] == 0x30 else {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derMalformed
            }
            index += 1
            let lengthData = try DistinguishedEncodingRulesLengthModel.decode(from: distinguishedEncodingRulesEncoded, startingAt: index)
            index = lengthData.nextIndex
            let endIndex = index + lengthData.length
            guard endIndex == distinguishedEncodingRulesEncoded.count else {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derMalformed
            }
            let rValue = try decodeInteger(from: distinguishedEncodingRulesEncoded, startingAt: &index)
            let sValue = try decodeInteger(from: distinguishedEncodingRulesEncoded, startingAt: &index)
            guard index == endIndex else {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derMalformed
            }
            return (rValue, sValue)
        }
        
        private static func encodeIntegerBytes(_ data: Data) -> Data {
            var bytes = [UInt8](data)
            while bytes.count > 1, bytes.first == 0 {
                bytes.removeFirst()
            }
            if let firstByte = bytes.first, firstByte & 0x80 != 0 {
                bytes.insert(0x00, at: 0)
            }
            return Data(bytes)
        }
        
        private static func decodeInteger(from data: Data, startingAt index: inout Int) throws -> Data {
            guard index < data.count else {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derMalformed
            }
            guard data[index] == 0x02 else {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derMalformed
            }
            index += 1
            let lengthData = try DistinguishedEncodingRulesLengthModel.decode(from: data, startingAt: index)
            index = lengthData.nextIndex
            let length = lengthData.length
            guard length > 0 else {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derMalformed
            }
            let endIndex = index + length
            guard endIndex <= data.count else {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derMalformed
            }
            let integerBytes = Array(data[index..<endIndex])
            index = endIndex
            guard let firstByte = integerBytes.first else {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derMalformed
            }
            if firstByte & 0x80 != 0 {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derNonCanonical
            }
            if integerBytes.count > 1, firstByte == 0x00, integerBytes[1] & 0x80 == 0 {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derNonCanonical
            }
            if integerBytes.count > 33 {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derMalformed
            }
            var valueBytes = integerBytes
            if valueBytes.count == 33 {
                guard valueBytes.first == 0x00 else {
                    throw StandardsForEfficientCryptography256k1CurveModel.Error.derNonCanonical
                }
                valueBytes.removeFirst()
            }
            if valueBytes.count < 32 {
                valueBytes.insert(contentsOf: repeatElement(0x00, count: 32 - valueBytes.count), at: 0)
            }
            guard valueBytes.count == 32 else {
                throw StandardsForEfficientCryptography256k1CurveModel.Error.derMalformed
            }
            return Data(valueBytes)
        }
    }
}
