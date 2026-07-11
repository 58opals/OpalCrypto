// OpalCryptoBenchmarks.MetalValidation~BitcoinCashSchnorrVectors.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks.MetalValidation {
    static func validateBitcoinCashSchnorrVectors() throws -> Int {
        let vectors = [
            BitcoinCashSchnorrVector(
                publicKeyHex: "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                digestHex: "0000000000000000000000000000000000000000000000000000000000000000",
                signatureHex: "787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05",
                expected: true
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                digestHex: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                signatureHex: "2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD",
                expected: true
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B",
                digestHex: "5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
                signatureHex: "00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380",
                expected: true
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
                digestHex: "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
                signatureHex: "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D",
                expected: true
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F",
                digestHex: "0000000000000000000000000000000000000000000000000000000000000000",
                signatureHex: "52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E3530B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187",
                expected: true
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B",
                digestHex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                signatureHex: "570DD4CA83D4E6317B8EE6BAE83467A1BF419D0767122DE409394414B05080DCE9EE5F237CBD108EABAE1E37759AE47F8E4203DA3532EB28DB860F33D62D49BD",
                expected: true
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "03EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
                digestHex: "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
                signatureHex: "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D",
                expected: false,
                isMetalPreparable: false
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                digestHex: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                signatureHex: "2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7",
                expected: false
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B",
                digestHex: "5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
                signatureHex: "00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BED092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC",
                expected: false
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                digestHex: "0000000000000000000000000000000000000000000000000000000000000000",
                signatureHex: "787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C",
                expected: false
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                digestHex: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                signatureHex: "2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD",
                expected: false
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                digestHex: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                signatureHex: "00000000000000000000000000000000000000000000000000000000000000009E9D01AF988B5CEDCE47221BFA9B222721F3FA408915444A4B489021DB55775F",
                expected: false
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                digestHex: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                signatureHex: "0000000000000000000000000000000000000000000000000000000000000001D37DDF0254351836D84B1BD6A795FD5D523048F298C4214D187FE4892947F728",
                expected: false
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                digestHex: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                signatureHex: "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD",
                expected: false
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                digestHex: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                signatureHex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD",
                expected: false,
                isMetalPreparable: false
            ),
            BitcoinCashSchnorrVector(
                publicKeyHex: "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
                digestHex: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
                signatureHex: "2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                expected: false,
                isMetalPreparable: false
            ),
        ]

        var checksum = 0
        var metalParityCount = 0
        var hostRejectionCount = 0
        for (index, vector) in vectors.enumerated() {
            let verificationKey = try? OpalCrypto.Signature.VerificationKey(
                rawRepresentation: decodeHex(vector.publicKeyHex)
            )
            let digest = try OpalCrypto.Signature.Digest(
                rawRepresentation: decodeHex(vector.digestHex)
            )
            let signature = try? OpalCrypto.Signature.Schnorr(
                rawRepresentation: decodeHex(vector.signatureHex)
            )
            guard vector.isMetalPreparable else {
                guard verificationKey == nil || signature == nil else {
                    throw Error.unexpectedResult(
                        "BCH Schnorr vector \(index + 1) should be rejected by the host"
                    )
                }
                hostRejectionCount += 1
                continue
            }
            guard let verificationKey, let signature else {
                throw Error.unexpectedResult(
                    "BCH Schnorr vector \(index + 1) was unexpectedly rejected by the host"
                )
            }
            let cpuResult = try signature.verify(
                digest: digest,
                verificationKey: verificationKey
            )
            guard cpuResult == vector.expected else {
                throw Error.unexpectedResult("BCH Schnorr vector \(index + 1)")
            }
            let input = try PerformanceBenchmarkOperations.makeMetalSchnorrVerificationInput(
                signature: signature,
                digest: digest,
                verificationKey: verificationKey
            )
            checksum ^= try OpalCryptoBenchmarks.MetalSchnorrVerificationCore.run(
                input: input,
                count: 1
            )
            checksum ^= cpuResult ? index + 1 : -(index + 1)
            metalParityCount += 1
        }

        print(
            "Metal BCH Schnorr vectors: \(vectors.count), "
                + "GPU parity: \(metalParityCount), host rejections: \(hostRejectionCount)"
        )
        return checksum
    }

}
