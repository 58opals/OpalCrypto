// BlindSignatureModel.swift

import Foundation

enum BlindSignatureModel {
    enum Error: Swift.Error, Equatable {
        case invalidPublicKeyLength(actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
        case invalidNoncePointLength(actual: Int)
        case invalidNoncePointPrefix(actual: UInt8)
        case invalidNoncePoint
        case invalidDigestLength(actual: Int)
        case invalidPrivateKeyLength(actual: Int)
        case invalidPrivateKey
        case invalidRequestLength(actual: Int)
        case invalidResponseLength(actual: Int)
        case randomGenerationFailed
        case nonceAlreadyUsed
        case verificationFailed
        case cryptographyFailure
    }

    struct RequestState: Sendable {
        let verificationKeyModel: VerificationKeyModel
        let messageDigest32Bytes: Data
        let signatureRData32Bytes: Data
        let requestScalar: ScalarModel
        let blindingScalarA: ScalarModel
        let isPositiveAdjustment: Bool

        init(
            signerPublicKey: Data,
            noncePoint: Data,
            messageDigest32Bytes: Data
        ) throws {
            guard messageDigest32Bytes.count == 32 else {
                throw Error.invalidDigestLength(actual: messageDigest32Bytes.count)
            }

            let derivedVerificationKeyModel: VerificationKeyModel
            do {
                derivedVerificationKeyModel = try VerificationKeyModel(publicKeyData: signerPublicKey)
            } catch VerificationKeyModel.Error.invalidPublicKeyLength(let actual) {
                throw Error.invalidPublicKeyLength(actual: actual)
            } catch VerificationKeyModel.Error.invalidPublicKeyPrefix(let actual) {
                throw Error.invalidPublicKeyPrefix(actual: actual)
            } catch {
                throw Error.invalidPublicKey
            }

            let nonceAffine: AffinePointModel
            do {
                nonceAffine = try PublicKeyParserModel.parsePublicKey(noncePoint)
            } catch PublicKeyParserModel.Error.invalidLength(let actual) {
                throw Error.invalidNoncePointLength(actual: actual)
            } catch PublicKeyParserModel.Error.invalidPrefix(let actual) {
                throw Error.invalidNoncePointPrefix(actual: actual)
            } catch {
                throw Error.invalidNoncePoint
            }

            let blindingScalarA: ScalarModel
            let blindingScalarB: ScalarModel
            do {
                blindingScalarA = try NonceGeneratorModel.makeSystemRandomScalar()
                blindingScalarB = try NonceGeneratorModel.makeSystemRandomScalar()
            } catch {
                throw Error.randomGenerationFailed
            }

            let adjustedPoint = JacobianPointModel(affine: nonceAffine)
                .add(ScalarMultiplicationModel.mulG(blindingScalarA))
                .add(
                    ScalarMultiplicationModel.mul(
                        blindingScalarB,
                        derivedVerificationKeyModel
                    )
                )
            guard !adjustedPoint.isInfinity else {
                throw Error.cryptographyFailure
            }

            let isPositiveAdjustment = adjustedPoint.Y.mul(adjustedPoint.Z).isQuadraticResidue
            let finalizedPoint = isPositiveAdjustment ? adjustedPoint : adjustedPoint.negate()
            guard let finalizedAffine = finalizedPoint.convertToAffine() else {
                throw Error.cryptographyFailure
            }

            let signatureRFieldElement = finalizedAffine.x
            let challengeScalar: ScalarModel
            do {
                challengeScalar = try ChallengeHashModel.makeChallengeScalar(
                    digest32: messageDigest32Bytes,
                    r: signatureRFieldElement,
                    verificationKeyModel: derivedVerificationKeyModel
                )
            } catch {
                throw Error.cryptographyFailure
            }

            self.verificationKeyModel = derivedVerificationKeyModel
            self.messageDigest32Bytes = messageDigest32Bytes
            self.signatureRData32Bytes = signatureRFieldElement.data32Bytes
            self.requestScalar = isPositiveAdjustment
                ? challengeScalar.addModN(blindingScalarB)
                : challengeScalar.negateModN().addModN(blindingScalarB)
            self.blindingScalarA = blindingScalarA
            self.isPositiveAdjustment = isPositiveAdjustment
        }

        func finalize(
            responseScalarData32Bytes: Data,
            verify: Bool
        ) throws -> Data {
            guard responseScalarData32Bytes.count == 32 else {
                throw Error.invalidResponseLength(actual: responseScalarData32Bytes.count)
            }

            let responseScalar: ScalarModel
            do {
                responseScalar = try ScalarConversionModel.makeReducedScalar(
                    from: responseScalarData32Bytes
                )
            } catch {
                throw Error.cryptographyFailure
            }

            let adjustedResponse = responseScalar.addModN(blindingScalarA)
            let signatureSScalar = isPositiveAdjustment
                ? adjustedResponse
                : adjustedResponse.negateModN()
            let signatureData = signatureRData32Bytes + signatureSScalar.data32Bytes

            guard verify else {
                return signatureData
            }

            let signature: SchnorrSignatureModel.Signature
            do {
                signature = try SchnorrSignatureModel.Signature(raw64ByteSignatureData: signatureData)
            } catch {
                throw Error.verificationFailed
            }
            let isValid: Bool
            do {
                isValid = try SchnorrSignatureModel.verify(
                    signature: signature,
                    digestData32Bytes: messageDigest32Bytes,
                    verificationKeyModel: verificationKeyModel
                )
            } catch {
                throw Error.verificationFailed
            }
            guard isValid else {
                throw Error.verificationFailed
            }
            return signatureData
        }
    }

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
            self.nonceScalar = nil

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

            let responseScalar = nonceScalar.addModN(
                requestScalar.mulModN(privateKeyScalar)
            )
            return responseScalar.data32Bytes
        }
    }
}
