// WindowedNonAdjacentFormCase.swift

@testable import OpalCrypto

enum WindowedNonAdjacentFormCase: CaseIterable, CustomStringConvertible, Sendable {
    case zero
    case positive
    case negative
    case highBit
    case splitFirst
    case splitSecond

    var description: String {
        switch self {
        case .zero:
            return "zero"
        case .positive:
            return "positive"
        case .negative:
            return "negative"
        case .highBit:
            return "highBit"
        case .splitFirst:
            return "splitFirst"
        case .splitSecond:
            return "splitSecond"
        }
    }

    func scalar() throws -> SignedScalar128Model {
        switch self {
        case .zero:
            return SignedScalar128Model(magnitude: .zero, isNegative: false)
        case .positive:
            return SignedScalar128Model(
                magnitude: Unsigned256BitIntegerModel(limbs: [15, 0, 0, 0]),
                isNegative: false
            )
        case .negative:
            return SignedScalar128Model(
                magnitude: Unsigned256BitIntegerModel(limbs: [15, 0, 0, 0]),
                isNegative: true
            )
        case .highBit:
            return SignedScalar128Model(
                magnitude: Unsigned256BitIntegerModel(limbs: [1, UInt64(1) << 63, 0, 0]),
                isNegative: false
            )
        case .splitFirst:
            return try Self.splitScalar().firstScalar
        case .splitSecond:
            return try Self.splitScalar().secondScalar
        }
    }

    private static func splitScalar() throws -> (
        firstScalar: SignedScalar128Model,
        secondScalar: SignedScalar128Model
    ) {
        try ScalarModel(
            data32: OpalCryptoTestSupport.makePrivateKey(37),
            requireNonZero: true
        ).splitForEndomorphism()
    }
}
