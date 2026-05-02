// OpalCrypto.Pedersen+Commitment.swift

import Foundation

extension OpalCrypto.Pedersen {
    public struct Commitment: Sendable, Equatable {
        internal let commitmentModel: PedersenModel.Commitment

        public var nonce: Nonce {
            Nonce(scalarModel: commitmentModel.nonceScalar)
        }

        public var point: CommitmentPoint {
            CommitmentPoint(affinePoint: commitmentModel.affinePoint)
        }

        internal init(commitmentModel: PedersenModel.Commitment) {
            self.commitmentModel = commitmentModel
        }

        public static func == (
            lhs: Commitment,
            rhs: Commitment
        ) -> Bool {
            lhs.commitmentModel == rhs.commitmentModel
        }
    }
}
