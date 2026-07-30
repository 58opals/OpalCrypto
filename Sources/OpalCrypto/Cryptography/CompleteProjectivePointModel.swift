// CompleteProjectivePointModel.swift

import Foundation

/// A homogeneous projective secp256k1 point used only by the hardened
/// secret-scalar multiplication path.
///
/// The addition and doubling formulas are the exception-free, `a = 0`
/// formulas from Renes, Costello, and Batina, "Complete addition formulas
/// for prime order elliptic curves" (Algorithms 7 and 9):
/// https://eprint.iacr.org/2015/1060
///
/// secp256k1 has prime order and cofactor one, and `PublicKey` parsing admits
/// only curve points. Those invariants make the formulas complete for every
/// point that can reach this type.
struct CompleteProjectivePointModel: Sendable {
    private let X: HardenedFieldElementModel
    private let Y: HardenedFieldElementModel
    private let Z: HardenedFieldElementModel

    static let infinity = CompleteProjectivePointModel(
        X: .zero,
        Y: .one,
        Z: .zero
    )

    init(affinePoint: AffinePointModel) {
        X = HardenedFieldElementModel(affinePoint.x)
        Y = HardenedFieldElementModel(affinePoint.y)
        Z = .one
    }

    private init(
        X: HardenedFieldElementModel,
        Y: HardenedFieldElementModel,
        Z: HardenedFieldElementModel
    ) {
        self.X = X
        self.Y = Y
        self.Z = Z
    }

    func add(
        _ other: CompleteProjectivePointModel
    ) -> CompleteProjectivePointModel {
        var xx = X.mul(other.X)
        var yy = Y.mul(other.Y)
        var zz = Z.mul(other.Z)
        let xyPairs = X
            .add(Y)
            .mul(other.X.add(other.Y))
            .sub(xx.add(yy))
        let yzPairs = Y
            .add(Z)
            .mul(other.Y.add(other.Z))
            .sub(yy.add(zz))
        let xzPairs = X
            .add(Z)
            .mul(other.X.add(other.Z))
            .sub(xx.add(zz))

        xx = xx.double().add(xx)
        zz = HardenedFieldElementModel.twentyOne.mul(zz)
        let yyPlusBzz3 = yy.add(zz)
        yy = yy.sub(zz)
        zz = HardenedFieldElementModel.twentyOne.mul(xzPairs)

        return CompleteProjectivePointModel(
            X: xyPairs.mul(yy).sub(yzPairs.mul(zz)),
            Y: zz.mul(xx).add(yy.mul(yyPlusBzz3)),
            Z: yyPlusBzz3.mul(yzPairs).add(xx.mul(xyPairs))
        )
    }

    func double() -> CompleteProjectivePointModel {
        var yy = Y.square()
        var outputZ = yy.double().double().double()
        let yz = Y.mul(Z)
        var bzz3 = HardenedFieldElementModel.twentyOne.mul(Z.square())
        let outputXFragment = bzz3.mul(outputZ)
        let outputYFragment = yy.add(bzz3)
        outputZ = yz.mul(outputZ)
        bzz3 = bzz3.double().add(bzz3)
        yy = yy.sub(bzz3)

        return CompleteProjectivePointModel(
            X: yy.mul(X.mul(Y)).double(),
            Y: outputXFragment.add(yy.mul(outputYFragment)),
            Z: outputZ
        )
    }

    var affinePoint: AffinePointModel? {
        guard !Z.isZero else {
            return nil
        }
        let zInverse = Z.invert()
        return AffinePointModel(
            x: X.mul(zInverse).fieldElementModel,
            y: Y.mul(zInverse).fieldElementModel
        )
    }

    var affineXCoordinateData32Bytes: Data {
        precondition(!Z.isZero)
        return X.mul(Z.invert()).data32Bytes
    }

    static func select(
        _ zeroValue: CompleteProjectivePointModel,
        _ oneValue: CompleteProjectivePointModel,
        bit: UInt64
    ) -> CompleteProjectivePointModel {
        CompleteProjectivePointModel(
            X: HardenedFieldElementModel.select(
                zeroValue.X,
                oneValue.X,
                bit: bit
            ),
            Y: HardenedFieldElementModel.select(
                zeroValue.Y,
                oneValue.Y,
                bit: bit
            ),
            Z: HardenedFieldElementModel.select(
                zeroValue.Z,
                oneValue.Z,
                bit: bit
            )
        )
    }
}
