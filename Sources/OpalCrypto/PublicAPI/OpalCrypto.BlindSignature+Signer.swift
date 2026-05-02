// OpalCrypto.BlindSignature+Signer.swift

import Foundation

extension OpalCrypto.BlindSignature {
    public actor Signer {
        internal var signerState: BlindSignatureModel.SignerState

        public nonisolated let noncePoint: OpalCrypto.Secp256k1.PublicKey

        public init() throws {
            do {
                let signerState = try BlindSignatureModel.SignerState()
                self.signerState = signerState
                self.noncePoint = try OpalCrypto.Secp256k1.PublicKey(
                    rawRepresentation: signerState.noncePointData
                )
            } catch let error as BlindSignatureModel.Error {
                throw OpalCrypto.BlindSignature.mapError(error)
            } catch let error as OpalCrypto.Secp256k1.Error {
                throw OpalCrypto.BlindSignature.mapSecp256k1Error(error)
            }
        }

        public func sign(
            privateKey: OpalCrypto.Secp256k1.PrivateKey,
            requestScalar: OpalCrypto.Secp256k1.Scalar
        ) async throws -> OpalCrypto.Secp256k1.Scalar {
            do {
                let responseScalar = try signerState.sign(
                    privateKey: privateKey.rawRepresentation,
                    requestScalarData32Bytes: requestScalar.rawRepresentation
                )
                return try OpalCrypto.Secp256k1.Scalar(rawRepresentation: responseScalar)
            } catch let error as BlindSignatureModel.Error {
                throw OpalCrypto.BlindSignature.mapError(error)
            } catch let error as OpalCrypto.Secp256k1.Error {
                throw OpalCrypto.BlindSignature.mapSecp256k1Error(error)
            }
        }
    }
}
