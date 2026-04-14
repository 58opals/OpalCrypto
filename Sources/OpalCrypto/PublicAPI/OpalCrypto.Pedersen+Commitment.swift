// OpalCrypto.Pedersen+Commitment.swift

import Foundation

extension OpalCrypto.Pedersen {
    public struct Commitment: Sendable, Equatable {
        internal let commitmentModel: PedersenModel.Commitment

        public var nonce: Data {
            commitmentModel.nonceData
        }

        public var compressedPoint: Data {
            commitmentModel.compressedPointData
        }

        public var uncompressedPoint: Data {
            commitmentModel.uncompressedPointData
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
