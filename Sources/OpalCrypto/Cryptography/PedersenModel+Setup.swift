// PedersenModel+Setup.swift

import Foundation

extension PedersenModel {
    struct Setup: Sendable, Equatable {
        let alternateBasePointModel: ParsedPublicKeyModel
        let alternatePlusGenerator: AffinePointModel

        init(alternateBasePoint: Data) throws {
            do {
                alternateBasePointModel = try ParsedPublicKeyModel(publicKeyData: alternateBasePoint)
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyLength(let actual) {
                throw Error.invalidAlternateBasePointLength(actual: actual)
            } catch ParsedPublicKeyModel.Error.invalidPublicKeyPrefix(let actual) {
                throw Error.invalidAlternateBasePointPrefix(actual: actual)
            } catch {
                throw Error.invalidAlternateBasePoint
            }

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
            let nonceScalar: ScalarModel
            if let nonceData32Bytes {
                do {
                    nonceScalar = try ScalarModel(
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
                do {
                    nonceScalar = try NonceGeneratorModel.makeSystemRandomScalar()
                } catch {
                    throw Error.cryptographyFailure
                }
            }

            let amountScalar = Self.makeAmountScalar(amount)
            let amountMinusNonce = amountScalar.subModN(nonceScalar)

            let offsetPoint = ScalarMultiplicationModel.mul(
                nonceScalar,
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
                nonceScalar: nonceScalar,
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

            let uncompressedPointData = try Self.addPoints(
                commitments.map(\.uncompressedPointData)
            )
            let affinePoint = try Self.parseCommitmentPointAffine(uncompressedPointData)
            return Commitment(
                setupIdentifier: firstCommitment.setupIdentifier,
                nonceScalar: nonceScalar,
                affinePoint: affinePoint
            )
        }

        static func addPoints(_ points: [Data]) throws -> Data {
            guard let firstPoint = points.first else {
                throw Error.emptyCommitmentList
            }

            var accumulator = JacobianPointModel(
                affine: try parseCommitmentPointAffine(firstPoint)
            )
            for point in points.dropFirst() {
                accumulator = accumulator.add(
                    JacobianPointModel(affine: try parseCommitmentPointAffine(point))
                )
            }
            guard let affinePoint = accumulator.convertToAffine() else {
                throw Error.invalidCommitment
            }
            return affinePoint.encodeUncompressed65()
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
