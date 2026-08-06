// BitcoinImprovementProposal340SignatureModel.swift

import Foundation

/// BIP340 signing and verification over the facade's fixed 32-byte digest.
///
/// BIP340 itself now permits arbitrary message sizes. OpalCrypto deliberately
/// retains the existing `Signature.Digest` boundary so callers own prehashing
/// and domain separation explicitly.
/// Specification: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
enum BitcoinImprovementProposal340SignatureModel {
    static func makeChallengeScalar(
        signatureRData32Bytes: Data,
        verificationKeyData32Bytes: Data,
        digestData32Bytes: Data
    ) -> ScalarModel {
        precondition(signatureRData32Bytes.count == 32)
        precondition(verificationKeyData32Bytes.count == 32)
        precondition(digestData32Bytes.count == 32)
        var input = Data()
        input.reserveCapacity(96)
        input.append(signatureRData32Bytes)
        input.append(verificationKeyData32Bytes)
        input.append(digestData32Bytes)
        return HardenedScalarArithmeticModel
            .reduceData32BytesModuloCurveOrder(
                makeTaggedHash(tag: challengeTag, input: input)
            )
    }

    static func makeTaggedHash(tag: Data, input: Data) -> Data {
        let tagHash = SecureHashAlgorithm256Model.hash(tag)
        var taggedInput = Data()
        taggedInput.reserveCapacity(64 + input.count)
        taggedInput.append(tagHash)
        taggedInput.append(tagHash)
        taggedInput.append(input)
        return SecureHashAlgorithm256Model.hash(taggedInput)
    }

    static func makeExclusiveOrData(
        _ left: Data,
        _ right: Data
    ) -> Data {
        precondition(left.count == right.count)
        return Data(zip(left, right).map { $0 ^ $1 })
    }

    static let auxiliaryTag = Data("BIP0340/aux".utf8)
    static let nonceTag = Data("BIP0340/nonce".utf8)
    static let challengeTag = Data("BIP0340/challenge".utf8)
}
