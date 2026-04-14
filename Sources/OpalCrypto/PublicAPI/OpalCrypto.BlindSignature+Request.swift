// OpalCrypto.BlindSignature+Request.swift

import Foundation

extension OpalCrypto.BlindSignature {
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
                throw OpalCrypto.BlindSignature.mapError(error)
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
                throw OpalCrypto.BlindSignature.mapError(error)
            }
        }
    }
}
