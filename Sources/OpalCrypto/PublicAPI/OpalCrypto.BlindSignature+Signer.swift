// OpalCrypto.BlindSignature+Signer.swift

import Foundation

extension OpalCrypto.BlindSignature {
    public actor Signer {
        internal var signerState: BlindSignatureModel.SignerState

        public nonisolated let noncePoint: Data

        public init() throws {
            do {
                let signerState = try BlindSignatureModel.SignerState()
                self.signerState = signerState
                self.noncePoint = signerState.noncePointData
            } catch let error as BlindSignatureModel.Error {
                throw OpalCrypto.BlindSignature.mapError(error)
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
                throw OpalCrypto.BlindSignature.mapError(error)
            }
        }
    }
}
