// OpalCrypto.Pedersen+Commitment.swift

import Foundation

extension OpalCrypto.Pedersen {
    /// A Pedersen commitment together with the nonce needed to open it.
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

        /// Returns whether two commitments contain the same setup, nonce, and point.
        public static func == (
            lhs: Commitment,
            rhs: Commitment
        ) -> Bool {
            lhs.commitmentModel == rhs.commitmentModel
        }
    }
}
