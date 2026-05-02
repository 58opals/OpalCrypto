// OpalCrypto.Pedersen+Setup.swift

import Foundation

extension OpalCrypto.Pedersen {
    public struct Setup: Sendable, Equatable {
        internal let setupModel: PedersenModel.Setup

        public init(alternateBasePoint: OpalCrypto.Secp256k1.PublicKey) throws {
            do {
                setupModel = try PedersenModel.Setup(
                    alternateBasePoint: alternateBasePoint.rawRepresentation
                )
            } catch let error as PedersenModel.Error {
                throw Self.mapError(error)
            }
        }

        public func commit(
            amount: Int64,
            nonce: Nonce? = nil
        ) throws -> Commitment {
            do {
                return Commitment(
                    commitmentModel: try setupModel.commit(
                        amount: amount,
                        nonceData32Bytes: nonce?.rawRepresentation
                    )
                )
            } catch let error as PedersenModel.Error {
                throw Self.mapError(error)
            }
        }

        public func verify(
            commitment: CommitmentPoint,
            amount: Int64,
            nonce: Nonce
        ) throws -> Bool {
            do {
                return try setupModel.verify(
                    commitmentPoint: commitment.rawRepresentation,
                    amount: amount,
                    nonceData32Bytes: nonce.rawRepresentation
                )
            } catch let error as PedersenModel.Error {
                throw Self.mapError(error)
            }
        }

        public func combine(
            _ commitments: [Commitment]
        ) throws -> Commitment {
            do {
                return Commitment(
                    commitmentModel: try setupModel.combine(
                        commitments.map(\.commitmentModel)
                    )
                )
            } catch let error as PedersenModel.Error {
                throw Self.mapError(error)
            }
        }

        public static func addPoints(_ points: [CommitmentPoint]) throws -> CommitmentPoint {
            do {
                let point = try PedersenModel.Setup.addPoints(
                    points.map(\.rawRepresentation)
                )
                return try CommitmentPoint(rawRepresentation: point)
            } catch let error as PedersenModel.Error {
                throw mapError(error)
            }
        }

        private static func mapError(_ error: PedersenModel.Error) -> Error {
            switch error {
            case .invalidAlternateBasePointLength(let actual):
                return .invalidAlternateBasePointLength(actual: actual)
            case .invalidAlternateBasePointPrefix(let actual):
                return .invalidAlternateBasePointPrefix(actual: actual)
            case .invalidAlternateBasePoint:
                return .invalidAlternateBasePoint
            case .insecureAlternateBasePoint:
                return .insecureAlternateBasePoint
            case .invalidNonceLength(let actual):
                return .invalidNonceLength(expected: 32, actual: actual)
            case .invalidNonce:
                return .invalidNonce
            case .invalidCommitmentLength(let actual):
                return .invalidCommitmentLength(actual: actual)
            case .invalidCommitment:
                return .invalidCommitment
            case .emptyCommitmentList:
                return .emptyCommitmentList
            case .mismatchedSetup:
                return .mismatchedSetup
            case .cryptographyFailure:
                return .cryptographyFailure
            }
        }
    }
}
