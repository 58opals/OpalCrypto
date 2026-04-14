// OpalCryptoBenchmarks+BenchmarkContext.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    struct BenchmarkContext: Sendable {
        let singlePrivateKey: Data
        let batch64PrivateKeys: [Data]
        let batch256PrivateKeys: [Data]
        let batch1024PrivateKeys: [Data]
        let batch256JacobianPointBufferModel: BatchJacobianPointBufferModel
        let batch1024JacobianPointBufferModel: BatchJacobianPointBufferModel
        let ecdsaMessage: Data
        let schnorrDigest: Data
        let compressedPublicKey: Data
        let verificationKey: OpalCrypto.Signature.VerificationKey
        let ecdsaSignature: Data
        let schnorrSignature: Data
        let mnemonic: OpalCrypto.Key.Mnemonic
        let mnemonicPhrase: String
        let basePayload: Data
        let base58EncodedPayload: String
        let base32EncodedPayload: String
        let rootExtendedPrivate: OpalCrypto.Key.ExtendedPrivate
        let rootExtendedPublic: OpalCrypto.Key.ExtendedPublic
        let genericPointMultiplicationScalar: Data
        let jointGeneratorScalar: Data
        let jointVerificationKeyScalar: Data
        let fieldSquareRootInput: Data
        let scalarInversionInput: Data

        static func make() throws -> BenchmarkContext {
            let singlePrivateKey = makePrivateKey(index: 1)
            let batch64PrivateKeys = (1...64).map(makePrivateKey(index:))
            let batch256PrivateKeys = (1...256).map(makePrivateKey(index:))
            let batch1024PrivateKeys = (1...1024).map(makePrivateKey(index:))
            let batch256JacobianPointBufferModel = try PerformanceBenchmarkSupportModel
                .makeBatchJacobianPointBuffer(from: batch256PrivateKeys)
            let batch1024JacobianPointBufferModel = try PerformanceBenchmarkSupportModel
                .makeBatchJacobianPointBuffer(from: batch1024PrivateKeys)
            let ecdsaMessage = Data("opalcrypto-benchmark-ecdsa".utf8)
            let schnorrDigest = OpalCrypto.Hashing.computeSHA256(
                Data("opalcrypto-benchmark-schnorr".utf8)
            )
            let compressedPublicKey = try OpalCrypto.Signature.derivePublicKey(
                fromPrivateKey: singlePrivateKey
            )
            let verificationKey = try OpalCrypto.Signature.deriveVerificationKey(
                fromPrivateKey: singlePrivateKey
            )
            let ecdsaSignature = try OpalCrypto.Signature.signECDSA(
                message: ecdsaMessage,
                privateKey: singlePrivateKey,
                format: .der
            )
            let schnorrSignature = try OpalCrypto.Signature.signSchnorr(
                digest: schnorrDigest,
                privateKey: singlePrivateKey,
                noncePolicy: .bip340Deterministic
            )
            let mnemonic = try OpalCrypto.Key.Mnemonic(
                phrase: """
                abandon abandon abandon abandon abandon abandon
                abandon abandon abandon abandon abandon about
                """,
                language: .english
            )
            let basePayload = Data((0..<64).map { UInt8(($0 * 17) & 0xff) })
            let base58EncodedPayload = OpalCrypto.Encoding.encodeBase58(basePayload)
            let base32EncodedPayload = try OpalCrypto.Encoding.encodeBase32(
                basePayload,
                interpretedAsFiveBitValues: false
            )
            let rootExtendedPrivate = try OpalCrypto.Key.ExtendedPrivate.root(
                seed: try mnemonic.deriveSeed(passphrase: "benchmark")
            )
            let rootExtendedPublic = rootExtendedPrivate.publicKey
            let genericPointMultiplicationScalar = makePrivateKey(index: 17)
            let jointGeneratorScalar = makePrivateKey(index: 19)
            let jointVerificationKeyScalar = makePrivateKey(index: 23)
            let fieldSquareRootInput = Data(
                [UInt8](repeating: 0x00, count: 31) + [0x04]
            )
            let scalarInversionInput = makePrivateKey(index: 29)

            return BenchmarkContext(
                singlePrivateKey: singlePrivateKey,
                batch64PrivateKeys: batch64PrivateKeys,
                batch256PrivateKeys: batch256PrivateKeys,
                batch1024PrivateKeys: batch1024PrivateKeys,
                batch256JacobianPointBufferModel: batch256JacobianPointBufferModel,
                batch1024JacobianPointBufferModel: batch1024JacobianPointBufferModel,
                ecdsaMessage: ecdsaMessage,
                schnorrDigest: schnorrDigest,
                compressedPublicKey: compressedPublicKey,
                verificationKey: verificationKey,
                ecdsaSignature: ecdsaSignature,
                schnorrSignature: schnorrSignature,
                mnemonic: mnemonic,
                mnemonicPhrase: mnemonic.phrase,
                basePayload: basePayload,
                base58EncodedPayload: base58EncodedPayload,
                base32EncodedPayload: base32EncodedPayload,
                rootExtendedPrivate: rootExtendedPrivate,
                rootExtendedPublic: rootExtendedPublic,
                genericPointMultiplicationScalar: genericPointMultiplicationScalar,
                jointGeneratorScalar: jointGeneratorScalar,
                jointVerificationKeyScalar: jointVerificationKeyScalar,
                fieldSquareRootInput: fieldSquareRootInput,
                scalarInversionInput: scalarInversionInput
            )
        }

        private static func makePrivateKey(index: Int) -> Data {
            var privateKey = Data(repeating: 0x00, count: 32)
            let resolvedIndex = UInt32(index)
            privateKey[28] = UInt8((resolvedIndex >> 24) & 0xff)
            privateKey[29] = UInt8((resolvedIndex >> 16) & 0xff)
            privateKey[30] = UInt8((resolvedIndex >> 8) & 0xff)
            privateKey[31] = UInt8(resolvedIndex & 0xff)
            return privateKey
        }
    }
}
