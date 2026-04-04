// OpalCrypto+Pedersen.swift

import Foundation

extension OpalCrypto {
    public enum Pedersen {
        public enum Error: Swift.Error, Equatable {
            case invalidAlternateBasePointLength(actual: Int)
            case invalidAlternateBasePointPrefix(actual: UInt8)
            case invalidAlternateBasePoint
            case insecureAlternateBasePoint
            case invalidNonceLength(expected: Int, actual: Int)
            case invalidNonce
            case invalidCommitmentLength(actual: Int)
            case invalidCommitment
            case emptyCommitmentList
            case mismatchedSetup
            case cryptographyFailure
        }

        public struct Setup: Sendable, Equatable {
            internal let setupModel: PedersenModel.Setup

            public init(alternateBasePoint: Data) throws {
                do {
                    setupModel = try PedersenModel.Setup(alternateBasePoint: alternateBasePoint)
                } catch let error as PedersenModel.Error {
                    throw Self.mapError(error)
                }
            }

            public func commit(
                amount: Int64,
                nonce: Data? = nil
            ) throws -> Commitment {
                do {
                    return Commitment(
                        commitmentModel: try setupModel.commit(
                            amount: amount,
                            nonceData32Bytes: nonce
                        )
                    )
                } catch let error as PedersenModel.Error {
                    throw Self.mapError(error)
                }
            }

            public func verify(
                commitment: Data,
                amount: Int64,
                nonce: Data
            ) throws -> Bool {
                do {
                    return try setupModel.verify(
                        commitmentPoint: commitment,
                        amount: amount,
                        nonceData32Bytes: nonce
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

            public static func addPoints(_ points: [Data]) throws -> Data {
                do {
                    return try PedersenModel.Setup.addPoints(points)
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
}
