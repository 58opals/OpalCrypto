// BlindSignatureModel+SignerState.swift

import Foundation

extension BlindSignatureModel {
    struct SignerState: Sendable {
        private var nonceScalar: ScalarModel?
        let noncePointData: Data

        init() throws {
            let nonceScalar: ScalarModel
            do {
                nonceScalar = try NonceGeneratorModel.makeSystemRandomScalar()
            } catch {
                throw Error.randomGenerationFailed
            }

            let noncePoint = ScalarMultiplicationModel.mulG(nonceScalar)
            guard let nonceAffine = noncePoint.convertToAffine() else {
                throw Error.cryptographyFailure
            }

            self.nonceScalar = nonceScalar
            self.noncePointData = nonceAffine.encodeCompressed33()
        }

        mutating func sign(
            privateKey: Data,
            requestScalarData32Bytes: Data
        ) throws -> Data {
            guard requestScalarData32Bytes.count == 32 else {
                throw Error.invalidRequestLength(actual: requestScalarData32Bytes.count)
            }

            guard nonceScalar != nil else {
                throw Error.nonceAlreadyUsed
            }

            let privateKeyScalar: ScalarModel
            do {
                privateKeyScalar = try ScalarModel(data32: privateKey, requireNonZero: true)
            } catch ScalarModel.Error.invalidDataLength(let expected, let actual) {
                precondition(expected == 32)
                throw Error.invalidPrivateKeyLength(actual: actual)
            } catch {
                throw Error.invalidPrivateKey
            }

            let requestScalar: ScalarModel
            do {
                requestScalar = try ScalarModel(
                    data32: requestScalarData32Bytes,
                    requireNonZero: false
                )
            } catch {
                throw Error.invalidRequestScalar
            }

            return try sign(
                privateKeyScalar: privateKeyScalar,
                requestScalar: requestScalar
            ).data32Bytes
        }

        mutating func sign(
            privateKeyScalar: ScalarModel,
            requestScalar: ScalarModel
        ) throws -> ScalarModel {
            guard let nonceScalar else {
                throw Error.nonceAlreadyUsed
            }

            self.nonceScalar = nil
            return nonceScalar.addModN(
                requestScalar.mulModN(privateKeyScalar)
            )
        }
    }
}
