// OpalCrypto.BlindSignature+Request.swift

import Foundation

extension OpalCrypto.BlindSignature {
        public struct Request: Sendable {
        internal let requestState: BlindSignatureModel.RequestState

        public var scalar: OpalCrypto.Secp256k1.Scalar {
            OpalCrypto.Secp256k1.Scalar(scalarModel: requestState.requestScalar)
        }

        public init(
            signerPublicKey: OpalCrypto.Secp256k1.PublicKey,
            noncePoint: OpalCrypto.Secp256k1.PublicKey,
            messageDigest: OpalCrypto.Signature.Digest
        ) throws {
            do {
                requestState = try BlindSignatureModel.RequestState(
                    signerPublicKey: signerPublicKey.rawRepresentation,
                    noncePoint: noncePoint.rawRepresentation,
                    messageDigest32Bytes: messageDigest.rawRepresentation
                )
            } catch let error as BlindSignatureModel.Error {
                throw OpalCrypto.BlindSignature.mapError(error)
            }
        }

        public func finalize(
            responseScalar: OpalCrypto.Secp256k1.Scalar,
            verify: Bool = true
        ) throws -> OpalCrypto.Signature.Schnorr {
            do {
                let signature = try requestState.finalize(
                    responseScalarData32Bytes: responseScalar.rawRepresentation,
                    verify: verify
                )
                return try OpalCrypto.Signature.Schnorr(rawRepresentation: signature)
            } catch let error as BlindSignatureModel.Error {
                throw OpalCrypto.BlindSignature.mapError(error)
            }
        }
    }
}
