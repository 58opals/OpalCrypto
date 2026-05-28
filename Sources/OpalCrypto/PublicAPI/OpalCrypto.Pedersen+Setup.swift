// OpalCrypto.Pedersen+Setup.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Pedersen {
    public struct Setup: Sendable, Equatable {
        internal let setupModel: PedersenModel.Setup

        public init(alternateBasePoint: OpalCrypto.Secp256k1.PublicKey) throws {
            let fields = [
                OpalDiagnostics.Field.operationField("setup"),
                OpalDiagnostics.Field.publicField("alternate_base_point_byte_count", alternateBasePoint.rawRepresentation.count)
            ]
            do {
                setupModel = try PedersenModel.Setup(
                    alternateBasePoint: alternateBasePoint.rawRepresentation
                )
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenSetupFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenSetupFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                event: OpalDiagnostics.Event.pedersenSetupSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenSetupSucceeded),
                fields: fields
            )
        }

        public func commit(
            amount: Int64,
            nonce: Nonce? = nil
        ) throws -> Commitment {
            let fields = [
                OpalDiagnostics.Field.operationField("commit"),
                OpalDiagnostics.Field.publicField("has_provided_nonce", nonce != nil)
            ]
            do {
                let commitment = Commitment(
                    commitmentModel: try setupModel.commit(
                        amount: amount,
                        nonceData32Bytes: nonce?.rawRepresentation
                    )
                )
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenCommitSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCommitSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.publicField("commitment_byte_count", commitment.point.rawRepresentation.count)
                    ]
                )
                return commitment
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenCommitFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCommitFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
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
                OpalDiagnostics.Field.operationField("verify"),
                OpalDiagnostics.Field.publicField("commitment_byte_count", commitment.rawRepresentation.count),
                OpalDiagnostics.Field.publicField("nonce_byte_count", nonce.rawRepresentation.count)
            ]
            do {
                let result = try setupModel.verify(
                    commitmentPoint: commitment.rawRepresentation,
                    amount: amount,
                    nonceData32Bytes: nonce.rawRepresentation
                )
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: result
                        ? OpalDiagnostics.Event.pedersenVerifySucceeded
                        : OpalDiagnostics.Event.pedersenVerifyFailed,
                    level: .opalCryptoDefault(for: result
                        ? OpalDiagnostics.Event.pedersenVerifySucceeded
                        : OpalDiagnostics.Event.pedersenVerifyFailed),
                    fields: fields + [OpalDiagnostics.Field.resultField(result)]
                )
                return result
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenVerifyFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenVerifyFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public func combine(
            _ commitments: [Commitment]
        ) throws -> Commitment {
            let fields = [
                OpalDiagnostics.Field.operationField("combine"),
                OpalDiagnostics.Field.publicField("commitment_count", commitments.count)
            ]
            do {
                let commitment = Commitment(
                    commitmentModel: try setupModel.combine(
                        commitments.map(\.commitmentModel)
                    )
                )
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenCombineSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCombineSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.publicField("commitment_byte_count", commitment.point.rawRepresentation.count)
                    ]
                )
                return commitment
            } catch let error as PedersenModel.Error {
                let mappedError = Self.mapError(error)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenCombineFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCombineFailed),
                    fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public static func addPoints(_ points: [CommitmentPoint]) throws -> CommitmentPoint {
            let fields = [
                OpalDiagnostics.Field.operationField("combine_points"),
                OpalDiagnostics.Field.publicField("point_count", points.count)
            ]
            do {
                let point = try PedersenModel.Setup.addPoints(
                    points.map(\.rawRepresentation)
                )
                let commitmentPoint = try CommitmentPoint(validatingRawRepresentation: point)
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                    event: OpalDiagnostics.Event.pedersenCombineSucceeded,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCombineSucceeded),
                    fields: fields + [
                        OpalDiagnostics.Field.publicField("commitment_byte_count", commitmentPoint.rawRepresentation.count)
                    ]
                )
                return commitmentPoint
            } catch let error as PedersenModel.Error {
                let mappedError = mapError(error)
                recordCombineFailed(mappedError, fields: fields)
                throw mappedError
            } catch let error as Error {
                recordCombineFailed(error, fields: fields)
                throw error
            }
        }

        private static func recordCombineFailed(
            _ error: Swift.Error,
            fields: [OpalDiagnostics.Field]
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.pedersen).record(
                event: OpalDiagnostics.Event.pedersenCombineFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.pedersenCombineFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(error)
            )
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
