// OpalCryptoBenchmarks~MetalValidation.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    enum MetalValidation {
        static func run() throws -> Int {
            let configuration = try MetalSchnorrVerificationCore.configuration()
            print("Metal validation configuration: \(configuration.description)")

            var checksum = try validateFieldOperations()
            checksum ^= try validateBitcoinCashSchnorrVectors()
            let generatedFixture = try makeGeneratedSchnorrFixture()
            checksum ^= try validateGeneratedSchnorrCorpus(generatedFixture)
            checksum ^= try validateWrongVerificationKey(generatedFixture)
            checksum ^= try validateVaryingVerificationKeys()
            return checksum
        }

        private static func validateFieldOperations() throws -> Int {
            let boundaryValues = try [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000002",
                "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D",
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E",
            ].map(decodeHex)

            var validationCases: [MetalFieldValidationBenchmarkCase] = .init()
            validationCases.reserveCapacity(10_000 + boundaryValues.count * boundaryValues.count)
            for left in boundaryValues {
                for right in boundaryValues {
                    validationCases.append(
                        try PerformanceBenchmarkOperations.makeMetalFieldValidationCase(
                            leftData32: left,
                            rightData32: right
                        )
                    )
                }
            }

            var generator = DeterministicGenerator(state: 0x4f70_616c_4d65_7461)
            var upperHalfGeneratedOperandCount = 0
            for _ in 0..<10_000 {
                let left = generator.nextCanonicalFieldBytes()
                let right = generator.nextCanonicalFieldBytes()
                upperHalfGeneratedOperandCount += left[0] & 0x80 == 0 ? 0 : 1
                upperHalfGeneratedOperandCount += right[0] & 0x80 == 0 ? 0 : 1
                validationCases.append(
                    try PerformanceBenchmarkOperations.makeMetalFieldValidationCase(
                        leftData32: left,
                        rightData32: right
                    )
                )
            }
            guard upperHalfGeneratedOperandCount > 0 else {
                throw Error.unexpectedResult(
                    "generated field cases did not cover the upper half of the field"
                )
            }

            let checksum = try MetalSchnorrVerificationCore.validateFieldOperations(
                validationCases
            )
            print("Metal field differential cases: \(validationCases.count)")
            print(
                "Metal upper-half generated field operands: "
                    + "\(upperHalfGeneratedOperandCount)"
            )
            return checksum
        }

        private static func validateBitcoinCashSchnorrVectors() throws -> Int {
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
                checksum ^= try MetalSchnorrVerificationCore.run(input: input, count: 1)
                checksum ^= cpuResult ? index + 1 : -(index + 1)
                metalParityCount += 1
            }

            print(
                "Metal BCH Schnorr vectors: \(vectors.count), "
                    + "GPU parity: \(metalParityCount), host rejections: \(hostRejectionCount)"
            )
            return checksum
        }

        private static func makeGeneratedSchnorrFixture() throws -> GeneratedSchnorrFixture {
            let privateKey = try makePrivateKey(lastByte: 1)
            let verificationKey = try OpalCrypto.Signature.deriveVerificationKey(from: privateKey)
            var signatures: [OpalCrypto.Signature.Schnorr] = .init()
            var digests: [OpalCrypto.Signature.Digest] = .init()
            signatures.reserveCapacity(8192)
            digests.reserveCapacity(8192)

            for index in 0..<8192 {
                let originalDigest = try OpalCrypto.Signature.Digest(
                    rawRepresentation: OpalCrypto.Hashing.sha256(
                        Data("opalcrypto-metal-validation-\(index)".utf8)
                    )
                )
                let originalSignature = try OpalCrypto.Signature.Schnorr.sign(
                    digest: originalDigest,
                    privateKey: privateKey,
                    noncePolicy: .bip340Deterministic
                )

                switch index % 32 {
                case 7:
                    var corruptedDigest = originalDigest.rawRepresentation
                    corruptedDigest[0] ^= 0x01
                    digests.append(
                        try OpalCrypto.Signature.Digest(rawRepresentation: corruptedDigest)
                    )
                    signatures.append(originalSignature)
                case 15, 23:
                    digests.append(originalDigest)
                    signatures.append(try makeCanonicalCorruptedSignature(originalSignature))
                default:
                    digests.append(originalDigest)
                    signatures.append(originalSignature)
                }
            }
            return GeneratedSchnorrFixture(
                verificationKey: verificationKey,
                signatures: signatures,
                digests: digests
            )
        }

        private static func validateGeneratedSchnorrCorpus(
            _ fixture: GeneratedSchnorrFixture
        ) throws -> Int {
            let tableWords = PerformanceBenchmarkOperations.makeMetalSchnorrVerificationTableWords(
                verificationKey: fixture.verificationKey
            )
            let cpuResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
                signatures: fixture.signatures,
                digests: fixture.digests,
                verificationKey: fixture.verificationKey
            )
            let expectedResults = cpuResults.map { $0 == 1 }
            let input = try PerformanceBenchmarkOperations.makeMetalSchnorrVerificationBatchInput(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: expectedResults,
                verificationKey: fixture.verificationKey,
                tableWords: tableWords
            )
            let metalChecksum = try MetalSchnorrVerificationCore.run(batchInput: input)
            print("Metal generated Schnorr corpus: \(fixture.signatures.count)")
            return metalChecksum ^ checksum(cpuResults)
        }

        private static func validateWrongVerificationKey(
            _ fixture: GeneratedSchnorrFixture
        ) throws -> Int {
            let wrongPrivateKey = try makePrivateKey(lastByte: 2)
            let wrongVerificationKey = try OpalCrypto.Signature.deriveVerificationKey(
                from: wrongPrivateKey
            )
            let tableWords = PerformanceBenchmarkOperations.makeMetalSchnorrVerificationTableWords(
                verificationKey: wrongVerificationKey
            )

            let cpuResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
                signatures: fixture.signatures,
                digests: fixture.digests,
                verificationKey: wrongVerificationKey
            )
            let input = try PerformanceBenchmarkOperations.makeMetalSchnorrVerificationBatchInput(
                signatures: fixture.signatures,
                digests: fixture.digests,
                expectedResults: cpuResults.map { $0 == 1 },
                verificationKey: wrongVerificationKey,
                tableWords: tableWords
            )
            let metalChecksum = try MetalSchnorrVerificationCore.run(batchInput: input)
            print("Metal wrong-key Schnorr corpus: \(fixture.signatures.count)")
            return metalChecksum ^ checksum(cpuResults)
        }

        private static func validateVaryingVerificationKeys() throws -> Int {
            let recordCount = 256
            var signatures: [OpalCrypto.Signature.Schnorr] = []
            var digests: [OpalCrypto.Signature.Digest] = []
            var verificationKeys: [OpalCrypto.Signature.VerificationKey] = []
            signatures.reserveCapacity(recordCount)
            digests.reserveCapacity(recordCount)
            verificationKeys.reserveCapacity(recordCount)

            for index in 0..<recordCount {
                let privateKey = try makePrivateKey(index: index)
                let signingKey = try privateKey.makeSigningKey()
                let digest = try OpalCrypto.Signature.Digest(
                    rawRepresentation: OpalCrypto.Hashing.sha256(
                        Data("opalcrypto-metal-varying-validation-\(index)".utf8)
                    )
                )
                signatures.append(try signingKey.signSchnorr(digest: digest))
                digests.append(digest)
                verificationKeys.append(signingKey.verificationKey)
            }

            verificationKeys[0] = verificationKeys[1]
            digests[1] = digests[2]
            signatures[2] = signatures[3]
            let cpuResults = try PerformanceBenchmarkOperations.verifySchnorrBatchSerial(
                signatures: signatures,
                digests: digests,
                verificationKeys: verificationKeys
            )
            let input = try PerformanceBenchmarkOperations
                .makeMetalSchnorrVaryingKeyVerificationBatchInput(
                    signatures: signatures,
                    digests: digests,
                    expectedResults: cpuResults.map { $0 == 1 },
                    verificationKeys: verificationKeys
                )
            let metalChecksum = try MetalSchnorrVerificationCore.run(
                varyingKeyBatchInput: input
            )
            print("Metal varying-key Schnorr corpus: \(recordCount)")
            return metalChecksum ^ checksum(cpuResults)
        }

        private static func makePrivateKey(
            lastByte: UInt8
        ) throws -> OpalCrypto.Secp256k1.PrivateKey {
            try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: Data([UInt8](repeating: 0, count: 31) + [lastByte])
            )
        }

        private static func makePrivateKey(
            index: Int
        ) throws -> OpalCrypto.Secp256k1.PrivateKey {
            var rawRepresentation = Data(repeating: 0, count: 32)
            let scalar = UInt32(index + 1)
            rawRepresentation[28] = UInt8(truncatingIfNeeded: scalar >> 24)
            rawRepresentation[29] = UInt8(truncatingIfNeeded: scalar >> 16)
            rawRepresentation[30] = UInt8(truncatingIfNeeded: scalar >> 8)
            rawRepresentation[31] = UInt8(truncatingIfNeeded: scalar)
            return try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: rawRepresentation
            )
        }

        private static func makeCanonicalCorruptedSignature(
            _ signature: OpalCrypto.Signature.Schnorr
        ) throws -> OpalCrypto.Signature.Schnorr {
            for byteIndex in stride(from: 63, through: 32, by: -1) {
                var bytes = signature.rawRepresentation
                bytes[byteIndex] ^= 0x01
                if let corrupted = try? OpalCrypto.Signature.Schnorr(
                    rawRepresentation: bytes
                ) {
                    return corrupted
                }
            }
            throw Error.unexpectedResult("could not construct canonical signature corruption")
        }

        private static func checksum(_ results: [UInt32]) -> Int {
            var checksum = 0
            for (index, result) in results.enumerated() {
                checksum ^= Int(result) &+ index
            }
            return checksum
        }

        private static func decodeHex(_ hex: String) throws -> Data {
            guard hex.count.isMultiple(of: 2) else {
                throw Error.invalidHex
            }
            var data = Data()
            data.reserveCapacity(hex.count / 2)
            var index = hex.startIndex
            while index < hex.endIndex {
                let nextIndex = hex.index(index, offsetBy: 2)
                guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
                    throw Error.invalidHex
                }
                data.append(byte)
                index = nextIndex
            }
            return data
        }

    }
}
