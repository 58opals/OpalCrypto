// MetalSchnorrBatchInputPreparationOperation~SelfTest.swift

import Foundation

extension MetalSchnorrBatchInputPreparationOperation {
    static func prepareSelfTestInputs() async throws -> (
        cachedKey: MetalSchnorrCachedKeyBatchInput,
        varyingKey: MetalSchnorrVaryingKeyBatchInput
    ) {
        let firstPublicKey = try OpalCrypto.Secp256k1.PublicKey(
            validatingRawRepresentation: try decodeSelfTestHex(
                "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            )
        )
        let secondPublicKey = try OpalCrypto.Secp256k1.PublicKey(
            validatingRawRepresentation: try decodeSelfTestHex(
                "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
            )
        )
        let zeroDigest = try OpalCrypto.Signature.Digest(
            rawRepresentation: Data(repeating: 0, count: 32)
        )
        let secondDigest = try OpalCrypto.Signature.Digest(
            rawRepresentation: try decodeSelfTestHex(
                "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
            )
        )
        let firstValidSignature = try OpalCrypto.Signature.Schnorr(
            rawRepresentation: try decodeSelfTestHex(
                "787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67"
                    + "031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05"
            )
        )
        let firstInvalidSignature = try OpalCrypto.Signature.Schnorr(
            rawRepresentation: try decodeSelfTestHex(
                "787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68"
                    + "FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C"
            )
        )
        let secondInvalidSignature = try OpalCrypto.Signature.Schnorr(
            rawRepresentation: try decodeSelfTestHex(
                "2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DF"
                    + "A16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7"
            )
        )
        let cachedSignatures = [firstValidSignature, firstInvalidSignature]
        let cachedDigests = [zeroDigest, zeroDigest]
        let cachedContext = makeCachedKeyContext(
            verificationKey: OpalCrypto.Signature.VerificationKey(
                publicKey: firstPublicKey
            )
        )
        let cachedKeyInput = try await prepareCachedKeyInput(
            signatures: cachedSignatures,
            digests: cachedDigests,
            range: cachedSignatures.indices,
            context: cachedContext
        )
        let varyingSignatures = [firstValidSignature, secondInvalidSignature]
        let varyingDigests = [zeroDigest, secondDigest]
        let varyingKeyInput = try await prepareVaryingKeyInput(
            signatures: varyingSignatures,
            digests: varyingDigests,
            publicKeys: [firstPublicKey, secondPublicKey],
            range: varyingSignatures.indices
        )
        return (cachedKeyInput, varyingKeyInput)
    }

    static func decodeSelfTestHex(_ value: String) throws -> Data {
        guard value.count.isMultiple(of: 2) else {
            throw MetalSchnorrBatchVerificationError.selfTestFailed
        }
        var data = Data()
        data.reserveCapacity(value.count / 2)
        var index = value.startIndex
        while index < value.endIndex {
            let nextIndex = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<nextIndex], radix: 16) else {
                throw MetalSchnorrBatchVerificationError.selfTestFailed
            }
            data.append(byte)
            index = nextIndex
        }
        return data
    }
}
