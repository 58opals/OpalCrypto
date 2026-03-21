// ChallengeHashModel.swift

import Foundation
import CryptoKit

enum ChallengeHashModel {
    enum Error: Swift.Error, Equatable {
        case invalidDigestLength(actual: Int)
    }
    
    static func makeChallengeScalar(
        digest32: Data,
        r: FieldElementModel,
        publicKey: AffinePointModel
    ) throws -> ScalarModel {
        try makeChallengeScalar(
            digest32: digest32,
            r: r,
            compressedPublicKeyData: publicKey.encodeCompressed33()
        )
    }

    static func makeChallengeScalar(
        digest32: Data,
        r: FieldElementModel,
        verificationKeyModel: VerificationKeyModel
    ) throws -> ScalarModel {
        try makeChallengeScalar(
            digest32: digest32,
            r: r,
            compressedPublicKeyData: verificationKeyModel.compressedPublicKeyData
        )
    }

    private static func makeChallengeScalar(
        digest32: Data,
        r: FieldElementModel,
        compressedPublicKeyData: Data
    ) throws -> ScalarModel {
        guard digest32.count == 32 else {
            throw Error.invalidDigestLength(actual: digest32.count)
        }
        var input = Data()
        input.reserveCapacity(97)
        input.appendUnsigned256BitIntegerBigEndian(r.value)
        input.append(compressedPublicKeyData)
        input.append(digest32)
        let hashData = SecureHashAlgorithm256Model.hash(input)
        let hashValue = try Unsigned256BitIntegerModel(contiguousBytes32: hashData)
        var reducedValue = hashValue
        if reducedValue.compare(to: StandardsForEfficientCryptography256k1CurveModel.Constant.n) != .orderedAscending {
            reducedValue = reducedValue.subtract(StandardsForEfficientCryptography256k1CurveModel.Constant.n).difference
        }
        return ScalarModel(unchecked: reducedValue)
    }
}
