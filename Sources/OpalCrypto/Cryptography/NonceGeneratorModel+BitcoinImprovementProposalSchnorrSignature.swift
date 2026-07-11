// NonceGeneratorModel+BitcoinImprovementProposalSchnorrSignature.swift

import Foundation
import CryptoKit

extension NonceGeneratorModel {
    struct BitcoinImprovementProposalSchnorrSignature {
        private let privateKeyData: Data
        private let digestData: Data
        private var counter: UInt32 = 0
        
        init(privateKey: ScalarModel, digest32: Data) throws {
            guard digest32.count == 32 else {
                throw ChallengeHashModel.Error.invalidDigestLength(actual: digest32.count)
            }
            privateKeyData = privateKey.data32
            digestData = digest32
        }
        
        mutating func makeNextScalar() throws -> ScalarModel {
            while true {
                var input = Data()
                input.append(privateKeyData)
                input.append(digestData)
                
                if counter != 0 {
                    var counterBigEndian = counter.bigEndian
                    // SAFETY: raw borrows the initialized UInt32 only for this
                    // closure, UInt8 has byte alignment, and append copies all
                    // four bytes before the stack value's lifetime ends.
                    withUnsafeBytes(of: &counterBigEndian) { raw in
                        input.append(contentsOf: raw.bindMemory(to: UInt8.self))
                    }
                }
                counter &+= 1
                
                let hashData = Data(SecureHashAlgorithm256Model.hash(input))
                let hashValue = try Unsigned256BitIntegerModel(data32: hashData)
                
                var reducedValue = hashValue
                if reducedValue.compare(to: StandardsForEfficientCryptography256k1CurveModel.Constant.n) != .orderedAscending {
                    reducedValue = reducedValue.subtract(StandardsForEfficientCryptography256k1CurveModel.Constant.n).difference
                }
                
                let scalar = ScalarModel(unchecked: reducedValue)
                guard !scalar.isZero else { continue }
                return scalar
            }
        }
    }
}
