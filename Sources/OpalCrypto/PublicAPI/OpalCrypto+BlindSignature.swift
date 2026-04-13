// OpalCrypto+BlindSignature.swift

import Foundation

extension OpalCrypto {
    public enum BlindSignature {
        public enum Error: Swift.Error, Equatable {
            case invalidPublicKeyLength(actual: Int)
            case invalidPublicKeyPrefix(actual: UInt8)
            case invalidPublicKey
            case invalidNoncePointLength(actual: Int)
            case invalidNoncePointPrefix(actual: UInt8)
            case invalidNoncePoint
            case invalidDigestLength(expected: Int, actual: Int)
            case invalidPrivateKeyLength(expected: Int, actual: Int)
            case invalidPrivateKey
            case invalidRequestLength(expected: Int, actual: Int)
            case invalidResponseLength(expected: Int, actual: Int)
            case nonceAlreadyUsed
            case cryptographyFailure
            case verificationFailed
        }

        public struct Request: Sendable {
            internal let requestState: BlindSignatureModel.RequestState

            public var scalar: Data {
                requestState.requestScalar.data32Bytes
            }

            public init(
                signerPublicKey: Data,
                noncePoint: Data,
                messageDigest: Data
            ) throws {
                do {
                    requestState = try BlindSignatureModel.RequestState(
                        signerPublicKey: signerPublicKey,
                        noncePoint: noncePoint,
                        messageDigest32Bytes: messageDigest
                    )
                } catch let error as BlindSignatureModel.Error {
                    throw BlindSignature.mapError(error)
                }
            }

            public func finalize(
                responseScalar: Data,
                verify: Bool = true
            ) throws -> Data {
                do {
                    return try requestState.finalize(
                        responseScalarData32Bytes: responseScalar,
                        verify: verify
                    )
                } catch let error as BlindSignatureModel.Error {
                    throw BlindSignature.mapError(error)
                }
            }
        }

        public actor Signer {
            internal var signerState: BlindSignatureModel.SignerState

            public nonisolated let noncePoint: Data

            public init() throws {
                do {
                    let signerState = try BlindSignatureModel.SignerState()
                    self.signerState = signerState
                    self.noncePoint = signerState.noncePointData
                } catch let error as BlindSignatureModel.Error {
                    throw BlindSignature.mapError(error)
                }
            }

            public func sign(
                privateKey: Data,
                requestScalar: Data
            ) async throws -> Data {
                do {
                    return try signerState.sign(
                        privateKey: privateKey,
                        requestScalarData32Bytes: requestScalar
                    )
                } catch let error as BlindSignatureModel.Error {
                    throw BlindSignature.mapError(error)
                }
            }
        }

        private static func mapError(_ error: BlindSignatureModel.Error) -> Error {
            switch error {
            case .invalidPublicKeyLength(let actual):
                return .invalidPublicKeyLength(actual: actual)
            case .invalidPublicKeyPrefix(let actual):
                return .invalidPublicKeyPrefix(actual: actual)
            case .invalidPublicKey:
                return .invalidPublicKey
            case .invalidNoncePointLength(let actual):
                return .invalidNoncePointLength(actual: actual)
            case .invalidNoncePointPrefix(let actual):
                return .invalidNoncePointPrefix(actual: actual)
            case .invalidNoncePoint:
                return .invalidNoncePoint
            case .invalidDigestLength(let actual):
                return .invalidDigestLength(expected: 32, actual: actual)
            case .invalidPrivateKeyLength(let actual):
                return .invalidPrivateKeyLength(expected: 32, actual: actual)
            case .invalidPrivateKey:
                return .invalidPrivateKey
            case .invalidRequestLength(let actual):
                return .invalidRequestLength(expected: 32, actual: actual)
            case .invalidResponseLength(let actual):
                return .invalidResponseLength(expected: 32, actual: actual)
            case .nonceAlreadyUsed:
                return .nonceAlreadyUsed
            case .randomGenerationFailed, .cryptographyFailure:
                return .cryptographyFailure
            case .verificationFailed:
                return .verificationFailed
            }
        }
    }
}
