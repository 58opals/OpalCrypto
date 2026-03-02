import Foundation
import Testing
@testable import OpalCrypto

@Suite("Standards for efficient cryptography 256k1 signature validation")
struct StandardsForEfficientCryptography256k1CurveSignatureValidator {
    @Test("Encode and decode distinguished encoding rules signature")
    func encodeAndDecodeDistinguishedEncodingRulesSignature() throws {
        let signature = try StandardsForEfficientCryptography256k1CurveModel.Signature(
            r: makeSignatureComponent(trailingByte: 0x01),
            s: makeSignatureComponent(trailingByte: 0x02)
        )

        let encoded = try signature.encodeDistinguishedEncodingRules()
        let decoded = try StandardsForEfficientCryptography256k1CurveModel.Signature(distinguishedEncodingRulesEncoded: encoded)

        #expect(decoded == signature)
    }

    @Test("Reject signature with zero scalar component")
    func rejectSignatureWithZeroScalarComponent() {
        let zeroComponent = Data(repeating: 0x00, count: 32)
        let nonZeroComponent = makeSignatureComponent(trailingByte: 0x01)
        do {
            _ = try StandardsForEfficientCryptography256k1CurveModel.Signature(
                r: zeroComponent,
                s: nonZeroComponent
            )
            Issue.record("Expected signature component zero error.")
        } catch let error as StandardsForEfficientCryptography256k1CurveModel.Error {
            #expect(error == .signatureComponentZero)
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Validate private key as invalid for zero and valid for one")
    func validatePrivateKeyAsInvalidForZeroAndValidForOne() {
        let zeroPrivateKey = Data(repeating: 0x00, count: 32)
        var onePrivateKey = Data(repeating: 0x00, count: 32)
        onePrivateKey[31] = 0x01

        #expect(
            !StandardsForEfficientCryptography256k1CurveModel.OperationModel.validatePrivateKeyData32Bytes(
                zeroPrivateKey
            )
        )
        #expect(
            StandardsForEfficientCryptography256k1CurveModel.OperationModel.validatePrivateKeyData32Bytes(
                onePrivateKey
            )
        )
    }

    @Test("Derive compressed public key from valid private key")
    func deriveCompressedPublicKeyFromValidPrivateKey() throws {
        var onePrivateKey = Data(repeating: 0x00, count: 32)
        onePrivateKey[31] = 0x01

        let publicKey = try StandardsForEfficientCryptography256k1CurveModel.OperationModel.derivePublicKey(
            fromPrivateKeyData32Bytes: onePrivateKey,
            format: .compressed
        )

        #expect(publicKey.count == 33)
        #expect(publicKey.first == 0x02 || publicKey.first == 0x03)
    }

    @Test("Reject public key derivation with invalid private key length")
    func rejectPublicKeyDerivationWithInvalidPrivateKeyLength() {
        let invalidLengthPrivateKey = Data(repeating: 0x01, count: 31)
        do {
            _ = try StandardsForEfficientCryptography256k1CurveModel.OperationModel.derivePublicKey(
                fromPrivateKeyData32Bytes: invalidLengthPrivateKey
            )
            Issue.record("Expected invalid private key length error.")
        } catch let error as StandardsForEfficientCryptography256k1CurveModel.OperationModel.Error {
            #expect(error == .invalidPrivateKeyLength(actual: 31))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    private func makeSignatureComponent(trailingByte: UInt8) -> Data {
        var component = Data(repeating: 0x00, count: 32)
        component[31] = trailingByte
        return component
    }
}
