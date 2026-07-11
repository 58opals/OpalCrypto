// PublicAPIBlindSignatureNonceStateValidator~RawContract.swift

import Foundation
import Testing
@testable import OpalCrypto

extension PublicAPIBlindSignatureNonceStateValidator {
    @Test("Raw blind signer preserves validation and nonce error ordering")
    func preserveRawBlindSignerValidationAndNonceErrorOrdering() throws {
        var signerState = try BlindSignatureModel.SignerState()

        do {
            _ = try signerState.sign(
                privateKey: Data(),
                requestScalarData32Bytes: Data(repeating: 0, count: 31)
            )
            Issue.record("Expected request-length validation before private-key validation.")
        } catch let error as BlindSignatureModel.Error {
            #expect(error == .invalidRequestLength(actual: 31))
        }

        let privateKey = try OpalCryptoTestSupport.makeTypedPrivateKey(11)
        _ = try signerState.sign(
            privateKeyScalar: privateKey.scalarModel,
            requestScalar: .zero
        )

        do {
            _ = try signerState.sign(
                privateKey: Data(),
                requestScalarData32Bytes: Data(repeating: 0, count: 32)
            )
            Issue.record("Expected nonce reuse rejection before private-key validation.")
        } catch let error as BlindSignatureModel.Error {
            #expect(error == .nonceAlreadyUsed)
        }
    }
}
