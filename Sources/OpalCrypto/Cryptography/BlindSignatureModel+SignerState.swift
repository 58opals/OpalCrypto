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

            guard let nonceScalar else {
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
                requestScalar = try ScalarConversionModel.makeReducedScalar(
                    from: requestScalarData32Bytes
                )
            } catch {
                throw Error.cryptographyFailure
            }

            self.nonceScalar = nil
            let responseScalar = nonceScalar.addModN(
                requestScalar.mulModN(privateKeyScalar)
            )
            return responseScalar.data32Bytes
        }
    }
}
