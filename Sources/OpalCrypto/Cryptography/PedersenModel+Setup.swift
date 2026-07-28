// PedersenModel+Setup.swift

import Foundation

extension PedersenModel {
    struct Setup: Sendable, Equatable {
        static let canonicalAlternateBasePointData =
            Data([0x02]) + Data("CashFusion gives us fungibility.".utf8)

        let alternateBasePointModel: ParsedPublicKeyModel
        let alternatePlusGenerator: AffinePointModel

        init() throws {
            try self.init(
                alternateBasePoint: Self.canonicalAlternateBasePointData
            )
        }

        init(alternateBasePoint: Data) throws {
            let alternateBasePointModel: ParsedPublicKeyModel
            do {
                alternateBasePointModel = try ParsedPublicKeyModel(publicKeyData: alternateBasePoint)
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyLength(let actual) {
                throw Error.invalidAlternateBasePointLength(actual: actual)
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyPrefix(let actual) {
                throw Error.invalidAlternateBasePointPrefix(actual: actual)
            } catch {
                throw Error.invalidAlternateBasePoint
            }

            try self.init(alternateBasePointModel: alternateBasePointModel)
        }

        init(alternateBasePointModel: ParsedPublicKeyModel) throws {
            guard alternateBasePointModel.compressedPublicKeyData
                == Self.canonicalAlternateBasePointData
            else {
                throw Error.insecureAlternateBasePoint
            }

            self.alternateBasePointModel = alternateBasePointModel

            guard alternateBasePointModel.affinePoint != ScalarMultiplicationModel.generator else {
                throw Error.insecureAlternateBasePoint
            }

            let combined = JacobianPointModel(affine: alternateBasePointModel.affinePoint)
                .addAffine(ScalarMultiplicationModel.generator)
            guard let alternatePlusGenerator = combined.convertToAffine() else {
                throw Error.insecureAlternateBasePoint
            }
            self.alternatePlusGenerator = alternatePlusGenerator
        }

        func commit(
            amount: Int64,
            nonceData32Bytes: Data? = nil
        ) throws -> Commitment {
            let parsedNonceScalar: ScalarModel?
            if let nonceData32Bytes {
                do {
                    parsedNonceScalar = try ScalarModel(
                        data32: nonceData32Bytes,
                        requireNonZero: false
                    )
                } catch ScalarModel.Error.invalidDataLength(let expected, let actual) {
                    precondition(expected == 32)
                    throw Error.invalidNonceLength(actual: actual)
                } catch {
                    throw Error.invalidNonce
                }
            } else {
                parsedNonceScalar = nil
            }
            return try commit(amount: amount, nonceScalar: parsedNonceScalar)
        }

        func commit(
            amount: Int64,
            nonceScalar: ScalarModel?
        ) throws -> Commitment {
            let resolvedNonceScalar: ScalarModel
            if let nonceScalar {
                resolvedNonceScalar = nonceScalar
            } else {
                do {
                    resolvedNonceScalar = try NonceGeneratorModel.makeSystemRandomScalar()
                } catch {
                    throw Error.cryptographyFailure
                }
            }

            let amountScalar = Self.makeAmountScalar(amount)
            let amountMinusNonce = amountScalar.subModN(resolvedNonceScalar)

            let offsetPoint = ScalarMultiplicationModel.mul(
                resolvedNonceScalar,
                alternatePlusGenerator
            )
            let resultPoint = amountMinusNonce.isZero
                ? offsetPoint
                : offsetPoint.add(
                    ScalarMultiplicationModel.mul(
                        amountMinusNonce,
                        alternateBasePointModel.affinePoint
                    )
                )
            guard let affinePoint = resultPoint.convertToAffine() else {
                throw Error.invalidCommitment
            }
            return Commitment(
                setupIdentifier: alternateBasePointModel.compressedPublicKeyData,
                nonceScalar: resolvedNonceScalar,
                affinePoint: affinePoint
            )
        }

        func verify(
            commitmentPoint: Data,
            amount: Int64,
            nonceData32Bytes: Data
        ) throws -> Bool {
            let expectedCommitment = try commit(
                amount: amount,
                nonceData32Bytes: nonceData32Bytes
            )
            let actualCommitment = try parseCommitmentPoint(commitmentPoint)
            return actualCommitment == expectedCommitment.uncompressedPointData
        }

        func verify(
            commitmentAffinePoint: AffinePointModel,
            amount: Int64,
            nonceScalar: ScalarModel
        ) throws -> Bool {
            let expectedCommitment = try commit(
                amount: amount,
                nonceScalar: nonceScalar
            )
            return commitmentAffinePoint == expectedCommitment.affinePoint
        }

        func combine(_ commitments: [Commitment]) throws -> Commitment {
            guard let firstCommitment = commitments.first else {
                throw Error.emptyCommitmentList
            }
            guard firstCommitment.setupIdentifier == alternateBasePointModel.compressedPublicKeyData else {
                throw Error.mismatchedSetup
            }
            guard commitments.allSatisfy({ $0.setupIdentifier == firstCommitment.setupIdentifier }) else {
                throw Error.mismatchedSetup
            }

            var nonceScalar = ScalarModel.zero
            for commitment in commitments {
                nonceScalar = nonceScalar.addModN(commitment.nonceScalar)
            }

            var accumulator = JacobianPointModel(affine: firstCommitment.affinePoint)
            for commitment in commitments.dropFirst() {
                accumulator = accumulator.add(
                    JacobianPointModel(affine: commitment.affinePoint)
                )
            }
            guard let affinePoint = accumulator.convertToAffine() else {
                throw Error.invalidCommitment
            }
            return Commitment(
                setupIdentifier: firstCommitment.setupIdentifier,
                nonceScalar: nonceScalar,
                affinePoint: affinePoint
            )
        }

        static func addPoints(_ points: [Data]) throws -> Data {
            guard !points.isEmpty else {
                throw Error.emptyCommitmentList
            }
            var affinePoints: [AffinePointModel] = .init()
            affinePoints.reserveCapacity(points.count)
            for point in points {
                affinePoints.append(try parseCommitmentPointAffine(point))
            }
            return try addAffinePoints(affinePoints).encodeUncompressed65()
        }

        static func addAffinePoints(
            _ affinePoints: [AffinePointModel]
        ) throws -> AffinePointModel {
            guard let firstPoint = affinePoints.first else {
                throw Error.emptyCommitmentList
            }
            var accumulator = JacobianPointModel(affine: firstPoint)
            for point in affinePoints.dropFirst() {
                accumulator = accumulator.add(JacobianPointModel(affine: point))
            }
            guard let affinePoint = accumulator.convertToAffine() else {
                throw Error.invalidCommitment
            }
            return affinePoint
        }

        private func parseCommitmentPoint(_ point: Data) throws -> Data {
            try Self.parseCommitmentPointAffine(point).encodeUncompressed65()
        }

        private static func parseCommitmentPointAffine(_ point: Data) throws -> AffinePointModel {
            do {
                return try PublicKeyParserModel.parsePublicKey(point)
            } catch PublicKeyParserModel.Error.invalidLength(let actual) {
                throw Error.invalidCommitmentLength(actual: actual)
            } catch {
                throw Error.invalidCommitment
            }
        }

        private static func makeAmountScalar(_ amount: Int64) -> ScalarModel {
            let magnitude = Unsigned256BitIntegerModel(
                limbs: [UInt64(amount.magnitude), 0, 0, 0]
            )
            let scalar = ScalarModel(unchecked: magnitude)
            return amount < 0 ? scalar.negateModN() : scalar
        }
    }
}
