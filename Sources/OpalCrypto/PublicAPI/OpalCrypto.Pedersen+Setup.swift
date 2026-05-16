// OpalCrypto.Pedersen+Setup.swift

import Foundation

extension OpalCrypto.Pedersen {
    public struct Setup: Sendable, Equatable {
        internal let setupModel: PedersenModel.Setup

        public init(alternateBasePoint: OpalCrypto.Secp256k1.PublicKey) throws {
            let fields = [
                OpalCryptoDiagnostics.operationField("setup"),
                OpalCryptoDiagnostics.publicField("alternate_base_point_byte_count", alternateBasePoint.rawRepresentation.count)
            ]
            do {
                setupModel = try PedersenModel.Setup(
                    alternateBasePoint: alternateBasePoint.rawRepresentation
                )
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenSetupFailed,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalCryptoDiagnostics.record(
                OpalCryptoDiagnostics.Event.pedersenSetupSucceeded,
                category: OpalCryptoDiagnostics.Category.pedersen,
                fields: fields
            )
        }

        public func commit(
            amount: Int64,
            nonce: Nonce? = nil
        ) throws -> Commitment {
            let fields = [
                OpalCryptoDiagnostics.operationField("commit"),
                OpalCryptoDiagnostics.publicField("has_provided_nonce", nonce != nil)
            ]
            do {
                let commitment = Commitment(
                    commitmentModel: try setupModel.commit(
                        amount: amount,
                        nonceData32Bytes: nonce?.rawRepresentation
                    )
                )
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenCommitSucceeded,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + [
                        OpalCryptoDiagnostics.publicField("commitment_byte_count", commitment.point.rawRepresentation.count)
                    ]
                )
                return commitment
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenCommitFailed,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public func verify(
            commitment: CommitmentPoint,
            amount: Int64,
            nonce: Nonce
        ) throws -> Bool {
            let fields = [
                OpalCryptoDiagnostics.operationField("verify"),
                OpalCryptoDiagnostics.publicField("commitment_byte_count", commitment.rawRepresentation.count),
                OpalCryptoDiagnostics.publicField("nonce_byte_count", nonce.rawRepresentation.count)
            ]
            do {
                let result = try setupModel.verify(
                    commitmentPoint: commitment.rawRepresentation,
                    amount: amount,
                    nonceData32Bytes: nonce.rawRepresentation
                )
                OpalCryptoDiagnostics.record(
                    result
                        ? OpalCryptoDiagnostics.Event.pedersenVerifySucceeded
                        : OpalCryptoDiagnostics.Event.pedersenVerifyFailed,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + [OpalCryptoDiagnostics.resultField(result)]
                )
                return result
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenVerifyFailed,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public func combine(
            _ commitments: [Commitment]
        ) throws -> Commitment {
            let fields = [
                OpalCryptoDiagnostics.operationField("combine"),
                OpalCryptoDiagnostics.publicField("commitment_count", commitments.count)
            ]
            do {
                let commitment = Commitment(
                    commitmentModel: try setupModel.combine(
                        commitments.map(\.commitmentModel)
                    )
                )
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenCombineSucceeded,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + [
                        OpalCryptoDiagnostics.publicField("commitment_byte_count", commitment.point.rawRepresentation.count)
                    ]
                )
                return commitment
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenCombineFailed,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public static func addPoints(_ points: [CommitmentPoint]) throws -> CommitmentPoint {
            let fields = [
                OpalCryptoDiagnostics.operationField("combine_points"),
                OpalCryptoDiagnostics.publicField("point_count", points.count)
            ]
            do {
                let point = try PedersenModel.Setup.addPoints(
                    points.map(\.rawRepresentation)
                )
                let commitmentPoint = try CommitmentPoint(rawRepresentation: point)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenCombineSucceeded,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + [
                        OpalCryptoDiagnostics.publicField("commitment_byte_count", commitmentPoint.rawRepresentation.count)
                    ]
                )
                return commitmentPoint
            } catch let error as PedersenModel.Error {
                let mappedError = mapError(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenCombineFailed,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            } catch let error as Error {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.pedersenCombineFailed,
                    category: OpalCryptoDiagnostics.Category.pedersen,
                    fields: fields + OpalCryptoDiagnostics.errorFields(error)
                )
                throw error
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
