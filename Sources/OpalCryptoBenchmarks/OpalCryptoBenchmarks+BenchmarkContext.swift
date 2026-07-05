// OpalCryptoBenchmarks+BenchmarkContext.swift

import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    struct BenchmarkContext: Sendable {
        let singlePrivateKeyData: Data
        let singlePrivateKey: OpalCrypto.Secp256k1.PrivateKey
        let batch64PrivateKeyData: [Data]
        let batch64PrivateKeys: [OpalCrypto.Secp256k1.PrivateKey]
        let batch64PublicKeys: [OpalCrypto.Secp256k1.PublicKey]
        let batch64PublicKeyData: [Data]
        let batch256PrivateKeyData: [Data]
        let batch256PrivateKeys: [OpalCrypto.Secp256k1.PrivateKey]
        let batch256PublicKeys: [OpalCrypto.Secp256k1.PublicKey]
        let batch256PublicKeyData: [Data]
        let batch1024PrivateKeyData: [Data]
        let batch1024PrivateKeys: [OpalCrypto.Secp256k1.PrivateKey]
        let batch1024PublicKeys: [OpalCrypto.Secp256k1.PublicKey]
        let batch1024PublicKeyData: [Data]
        let batch256JacobianPointBuffer: BatchJacobianPointBuffer
        let batch1024JacobianPointBuffer: BatchJacobianPointBuffer
        let ecdsaMessage: Data
        let ecdsaDigest: OpalCrypto.Signature.Digest
        let schnorrDigest: OpalCrypto.Signature.Digest
        let compressedPublicKey: OpalCrypto.Secp256k1.PublicKey
        let verificationKey: OpalCrypto.Signature.VerificationKey
        let ecdsaSignature: OpalCrypto.Signature.ECDSA
        let schnorrSignature: OpalCrypto.Signature.Schnorr
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
            let singlePrivateKeyData = makePrivateKey(index: 1)
            let singlePrivateKey = try OpalCrypto.Secp256k1.PrivateKey(
                rawRepresentation: singlePrivateKeyData
            )
            let batch64PrivateKeyData = (1...64).map(makePrivateKey(index:))
            let batch64PrivateKeys = try batch64PrivateKeyData.map {
                try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: $0)
            }
            let batch64PublicKeys = try batch64PrivateKeys.map {
                try OpalCrypto.Secp256k1.derivePublicKey(from: $0)
            }
            let batch64PublicKeyData = batch64PublicKeys.map(\.rawRepresentation)
            let batch256PrivateKeyData = (1...256).map(makePrivateKey(index:))
            let batch256PrivateKeys = try batch256PrivateKeyData.map {
                try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: $0)
            }
            let batch256PublicKeys = try batch256PrivateKeys.map {
                try OpalCrypto.Secp256k1.derivePublicKey(from: $0)
            }
            let batch256PublicKeyData = batch256PublicKeys.map(\.rawRepresentation)
            let batch1024PrivateKeyData = (1...1024).map(makePrivateKey(index:))
            let batch1024PrivateKeys = try batch1024PrivateKeyData.map {
                try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: $0)
            }
            let batch1024PublicKeys = try batch1024PrivateKeys.map {
                try OpalCrypto.Secp256k1.derivePublicKey(from: $0)
            }
            let batch1024PublicKeyData = batch1024PublicKeys.map(\.rawRepresentation)
            let batch256JacobianPointBuffer = try PerformanceBenchmarkOperations
                .makeBatchJacobianPointBuffer(from: batch256PrivateKeyData)
            let batch1024JacobianPointBuffer = try PerformanceBenchmarkOperations
                .makeBatchJacobianPointBuffer(from: batch1024PrivateKeyData)
            let ecdsaMessage = Data("opalcrypto-benchmark-ecdsa".utf8)
            let ecdsaDigest = try OpalCrypto.Signature.Digest(
                rawRepresentation: OpalCrypto.Hashing.sha256(ecdsaMessage)
            )
            let schnorrDigest = try OpalCrypto.Signature.Digest(
                rawRepresentation: OpalCrypto.Hashing.sha256(
                    Data("opalcrypto-benchmark-schnorr".utf8)
                )
            )
            let compressedPublicKey = try OpalCrypto.Secp256k1.derivePublicKey(
                from: singlePrivateKey
            )
            let verificationKey = try OpalCrypto.Signature.deriveVerificationKey(
                from: singlePrivateKey
            )
            let ecdsaSignature = try OpalCrypto.Signature.ECDSA.sign(
                message: ecdsaMessage,
                privateKey: singlePrivateKey,
                format: .der
            )
            let schnorrSignature = try OpalCrypto.Signature.Schnorr.sign(
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
            let base32EncodedPayload = try OpalCrypto.Encoding.encodeBase32Bytes(basePayload)
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
                singlePrivateKeyData: singlePrivateKeyData,
                singlePrivateKey: singlePrivateKey,
                batch64PrivateKeyData: batch64PrivateKeyData,
                batch64PrivateKeys: batch64PrivateKeys,
                batch64PublicKeys: batch64PublicKeys,
                batch64PublicKeyData: batch64PublicKeyData,
                batch256PrivateKeyData: batch256PrivateKeyData,
                batch256PrivateKeys: batch256PrivateKeys,
                batch256PublicKeys: batch256PublicKeys,
                batch256PublicKeyData: batch256PublicKeyData,
                batch1024PrivateKeyData: batch1024PrivateKeyData,
                batch1024PrivateKeys: batch1024PrivateKeys,
                batch1024PublicKeys: batch1024PublicKeys,
                batch1024PublicKeyData: batch1024PublicKeyData,
                batch256JacobianPointBuffer: batch256JacobianPointBuffer,
                batch1024JacobianPointBuffer: batch1024JacobianPointBuffer,
                ecdsaMessage: ecdsaMessage,
                ecdsaDigest: ecdsaDigest,
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
