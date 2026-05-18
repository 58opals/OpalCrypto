// OpalDiagnostics+OpalCrypto.swift

import Foundation
import OpalDiagnostics

extension OpalDiagnostics.Category {
    static let signature = OpalDiagnostics.Category(rawValue: "crypto.signature")
    static let key = OpalDiagnostics.Category(rawValue: "crypto.key")
    static let keyDerivation = OpalDiagnostics.Category(rawValue: "crypto.key_derivation")
    static let encoding = OpalDiagnostics.Category(rawValue: "crypto.encoding")
    static let communication = OpalDiagnostics.Category(rawValue: "crypto.communication")
    static let blindSignature = OpalDiagnostics.Category(rawValue: "crypto.blind_signature")
    static let pedersen = OpalDiagnostics.Category(rawValue: "crypto.pedersen")
    static let hashing = OpalDiagnostics.Category(rawValue: "crypto.hashing")
}

extension OpalDiagnostics.Event {
    static let ecdsaSignBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.sign.begin")
    static let ecdsaSignSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.sign.succeeded")
    static let ecdsaSignFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.sign.failed")
    static let ecdsaVerifyBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.verify.begin")
    static let ecdsaVerifySucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.verify.succeeded")
    static let ecdsaVerifyFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.verify.failed")
    static let schnorrSignBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.sign.begin")
    static let schnorrSignSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.sign.succeeded")
    static let schnorrSignFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.sign.failed")
    static let schnorrVerifyBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.verify.begin")
    static let schnorrVerifySucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.verify.succeeded")
    static let schnorrVerifyFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.verify.failed")
    static let verificationKeyDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.verification_key.derive.succeeded")
    static let verificationKeyDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.verification_key.derive.failed")
    static let verificationKeyParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.verification_key.parse.succeeded")
    static let verificationKeyParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.verification_key.parse.failed")

    static let privateKeyGenerateSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.generate.succeeded")
    static let privateKeyGenerateFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.generate.failed")
    static let privateKeyParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.parse.succeeded")
    static let privateKeyParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.parse.failed")
    static let privateKeyTweakAddSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.tweak_add.succeeded")
    static let privateKeyTweakAddFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.tweak_add.failed")
    static let publicKeyParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.parse.succeeded")
    static let publicKeyParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.parse.failed")
    static let publicKeyDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.derive.succeeded")
    static let publicKeyDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.derive.failed")
    static let publicKeysDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.batch_derive.succeeded")
    static let publicKeysDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.batch_derive.failed")
    static let publicKeyTweakAddSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.tweak_add.succeeded")
    static let publicKeyTweakAddFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.tweak_add.failed")
    static let sharedSecretDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.shared_secret.derive.succeeded")
    static let sharedSecretDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.shared_secret.derive.failed")
    static let sharedSecretParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.shared_secret.parse.succeeded")
    static let sharedSecretParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.shared_secret.parse.failed")
    static let wifParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.parse.succeeded")
    static let wifParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.parse.failed")
    static let wifSerializeSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.serialize.succeeded")
    static let wifSerializeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.serialize.failed")
    static let mnemonicParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.parse.succeeded")
    static let mnemonicParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.parse.failed")
    static let mnemonicGenerateSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.generate.succeeded")
    static let mnemonicGenerateFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.generate.failed")
    static let mnemonicSeedDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.seed.derive.succeeded")
    static let mnemonicSeedDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.seed.derive.failed")
    static let extendedPrivateParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.parse.succeeded")
    static let extendedPrivateParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.parse.failed")
    static let extendedPrivateRootSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.root.succeeded")
    static let extendedPrivateRootFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.root.failed")
    static let extendedPublicParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_public.parse.succeeded")
    static let extendedPublicParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_public.parse.failed")

    static let pbkdf2DeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key_derivation.pbkdf2.derive.succeeded")
    static let pbkdf2DeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key_derivation.pbkdf2.derive.failed")

    static let communicationEncryptBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.encrypt.begin")
    static let communicationEncryptSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.encrypt.succeeded")
    static let communicationEncryptFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.encrypt.failed")
    static let communicationDecryptBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.decrypt.begin")
    static let communicationDecryptSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.decrypt.succeeded")
    static let communicationDecryptFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.decrypt.failed")
    static let communicationCiphertextParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.ciphertext.parse.succeeded")
    static let communicationCiphertextParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.ciphertext.parse.failed")
    static let communicationSymmetricKeyParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.symmetric_key.parse.succeeded")
    static let communicationSymmetricKeyParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.symmetric_key.parse.failed")

    static let blindSignatureRequestBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.request.begin")
    static let blindSignatureRequestSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.request.succeeded")
    static let blindSignatureRequestFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.request.failed")
    static let blindSignatureSignerPrepareSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.signer.prepare.succeeded")
    static let blindSignatureSignerPrepareFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.signer.prepare.failed")
    static let blindSignatureSignBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.sign.begin")
    static let blindSignatureSignSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.sign.succeeded")
    static let blindSignatureSignFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.sign.failed")
    static let blindSignatureUnblindBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.unblind.begin")
    static let blindSignatureUnblindSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.unblind.succeeded")
    static let blindSignatureUnblindFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.unblind.failed")
    static let blindSignatureVerifySucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.verify.succeeded")
    static let blindSignatureVerifyFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.verify.failed")

    static let pedersenSetupSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.setup.succeeded")
    static let pedersenSetupFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.setup.failed")
    static let pedersenCommitSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.commit.succeeded")
    static let pedersenCommitFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.commit.failed")
    static let pedersenVerifySucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.verify.succeeded")
    static let pedersenVerifyFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.verify.failed")
    static let pedersenCombineSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.combine.succeeded")
    static let pedersenCombineFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.combine.failed")
    static let pedersenCommitmentParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.commitment.parse.succeeded")
    static let pedersenCommitmentParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.commitment.parse.failed")
    static let pedersenNonceParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.nonce.parse.succeeded")
    static let pedersenNonceParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.nonce.parse.failed")

    static let sha256Succeeded = OpalDiagnostics.Event(rawValue: "opalcrypto.hashing.sha256.succeeded")
    static let hash256Succeeded = OpalDiagnostics.Event(rawValue: "opalcrypto.hashing.hash256.succeeded")
    static let hash160Succeeded = OpalDiagnostics.Event(rawValue: "opalcrypto.hashing.hash160.succeeded")
    static let hmacSHA512Succeeded = OpalDiagnostics.Event(rawValue: "opalcrypto.hashing.hmac_sha512.succeeded")
    static let hmacSHA256Succeeded = OpalDiagnostics.Event(rawValue: "opalcrypto.hashing.hmac_sha256.succeeded")

    static let base58DecodeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.encoding.base58.decode.failed")
    static let base58CheckDecodeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.encoding.base58check.decode.failed")
    static let base32DecodeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.encoding.base32.decode.failed")
}

extension OpalDiagnostics.Level {
    static func opalCryptoDefault(for event: OpalDiagnostics.Event) -> OpalDiagnostics.Level {
        event.rawValue.hasSuffix(".failed") ? .error : .debug
    }
}

extension OpalDiagnostics.Field {
    static func publicField(_ name: String, _ value: String) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, publicValue: value)
    }

    static func publicField(_ name: String, _ value: Int) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, value: value)
    }

    static func publicField(_ name: String, _ value: Bool) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, value: value)
    }

    static func privateField(_ name: String, _ value: String) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, value: value, privacy: .private)
    }

    static func operationField(_ operation: String) -> OpalDiagnostics.Field {
        publicField("operation", operation)
    }

    static func algorithmField(_ algorithm: String) -> OpalDiagnostics.Field {
        publicField("algorithm", algorithm)
    }

    static func formatField(_ format: String) -> OpalDiagnostics.Field {
        publicField("format", format)
    }

    static func inputLengthField(_ count: Int) -> OpalDiagnostics.Field {
        publicField("input_byte_count", count)
    }

    static func outputLengthField(_ count: Int) -> OpalDiagnostics.Field {
        publicField("output_byte_count", count)
    }

    static func messageLengthField(_ count: Int) -> OpalDiagnostics.Field {
        publicField("message_byte_count", count)
    }

    static func signatureLengthField(_ count: Int) -> OpalDiagnostics.Field {
        publicField("signature_byte_count", count)
    }

    static func ciphertextLengthField(_ count: Int) -> OpalDiagnostics.Field {
        publicField("ciphertext_byte_count", count)
    }

    static func resultField(_ result: Bool) -> OpalDiagnostics.Field {
        publicField("verification_result", result)
    }

    static func errorFields(_ error: Swift.Error) -> [OpalDiagnostics.Field] {
        [
            OpalDiagnostics.Field.errorCode(errorCode(for: error)),
            OpalDiagnostics.Field.errorType(error),
            OpalDiagnostics.Field.errorMessage(String(describing: error))
        ]
    }

    private static func errorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode {
        switch error {
        case OpalCrypto.Secp256k1.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.Secp256k1.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey
        case OpalCrypto.Secp256k1.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.Secp256k1.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.Secp256k1.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey
        case OpalCrypto.Secp256k1.Error.invalidTweakLength:
            OpalDiagnostics.ErrorCode.invalidTweakLength
        case OpalCrypto.Secp256k1.Error.invalidTweak:
            OpalDiagnostics.ErrorCode.invalidTweak
        case OpalCrypto.Secp256k1.Error.invalidDerivedKey:
            OpalDiagnostics.ErrorCode.invalidDerivedKey
        case OpalCrypto.Secp256k1.Error.invalidSignatureLength:
            OpalDiagnostics.ErrorCode.invalidSignatureLength
        case OpalCrypto.Secp256k1.Error.invalidSignature:
            OpalDiagnostics.ErrorCode.invalidSignature
        case OpalCrypto.Secp256k1.Error.invalidDER:
            OpalDiagnostics.ErrorCode.invalidDER
        case OpalCrypto.Secp256k1.Error.nonCanonicalDER:
            OpalDiagnostics.ErrorCode.nonCanonicalDER
        case OpalCrypto.Secp256k1.Error.randomGenerationFailed:
            OpalDiagnostics.ErrorCode.randomGenerationFailed

        case OpalCrypto.Signature.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.Signature.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey
        case OpalCrypto.Signature.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.Signature.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.Signature.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey
        case OpalCrypto.Signature.Error.invalidDigestLength:
            OpalDiagnostics.ErrorCode.invalidDigestLength
        case OpalCrypto.Signature.Error.invalidSignatureLength:
            OpalDiagnostics.ErrorCode.invalidSignatureLength
        case OpalCrypto.Signature.Error.invalidSignature:
            OpalDiagnostics.ErrorCode.invalidSignature
        case OpalCrypto.Signature.Error.invalidDER:
            OpalDiagnostics.ErrorCode.invalidDER
        case OpalCrypto.Signature.Error.nonCanonicalDER:
            OpalDiagnostics.ErrorCode.nonCanonicalDER
        case OpalCrypto.Signature.Error.cryptographyFailure:
            OpalDiagnostics.ErrorCode.cryptographyFailure

        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey

        case OpalCrypto.KeyDerivation.Error.invalidIterationCount:
            OpalDiagnostics.ErrorCode.invalidIterationCount
        case OpalCrypto.KeyDerivation.Error.emptySalt:
            OpalDiagnostics.ErrorCode.emptySalt
        case OpalCrypto.KeyDerivation.Error.invalidDerivedKeyLength:
            OpalDiagnostics.ErrorCode.invalidDerivedKeyLength
        case OpalCrypto.KeyDerivation.Error.derivedKeyLengthExceedsLimit:
            OpalDiagnostics.ErrorCode.derivedKeyLengthExceedsLimit

        case OpalCrypto.Key.Mnemonic.Error.invalidWordCount:
            OpalDiagnostics.ErrorCode.invalidWordCount
        case OpalCrypto.Key.Mnemonic.Error.invalidEntropyLength:
            OpalDiagnostics.ErrorCode.invalidEntropyLength
        case OpalCrypto.Key.Mnemonic.Error.invalidWord:
            OpalDiagnostics.ErrorCode.invalidWord
        case OpalCrypto.Key.Mnemonic.Error.invalidChecksum:
            OpalDiagnostics.ErrorCode.invalidChecksum
        case OpalCrypto.Key.Mnemonic.Error.ambiguousLanguage:
            OpalDiagnostics.ErrorCode.ambiguousLanguage
        case OpalCrypto.Key.Mnemonic.Error.randomGenerationFailed:
            OpalDiagnostics.ErrorCode.randomGenerationFailed
        case OpalCrypto.Key.Mnemonic.Error.wordListResourceMissing:
            OpalDiagnostics.ErrorCode.wordListResourceMissing
        case OpalCrypto.Key.Mnemonic.Error.invalidWordList:
            OpalDiagnostics.ErrorCode.invalidWordList

        case OpalCrypto.Key.WIF.Error.invalidBase58:
            OpalDiagnostics.ErrorCode.invalidBase58
        case OpalCrypto.Key.WIF.Error.invalidChecksum:
            OpalDiagnostics.ErrorCode.invalidChecksum
        case OpalCrypto.Key.WIF.Error.invalidPayloadLength:
            OpalDiagnostics.ErrorCode.invalidPayloadLength
        case OpalCrypto.Key.WIF.Error.invalidVersion:
            OpalDiagnostics.ErrorCode.invalidVersion
        case OpalCrypto.Key.WIF.Error.invalidCompressionMarker:
            OpalDiagnostics.ErrorCode.invalidCompressionMarker
        case OpalCrypto.Key.WIF.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.Key.WIF.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey

        case OpalCrypto.Key.ExtendedPrivate.Error.invalidBase58:
            OpalDiagnostics.ErrorCode.invalidBase58
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidChecksum:
            OpalDiagnostics.ErrorCode.invalidChecksum
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidVersion:
            OpalDiagnostics.ErrorCode.invalidVersion
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPayloadLength:
            OpalDiagnostics.ErrorCode.invalidPayloadLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidParentFingerprintLength:
            OpalDiagnostics.ErrorCode.invalidParentFingerprintLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidChainCodeLength:
            OpalDiagnostics.ErrorCode.invalidChainCodeLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidSeedLength:
            OpalDiagnostics.ErrorCode.invalidSeedLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidDepthMetadata:
            OpalDiagnostics.ErrorCode.invalidDepthMetadata
        case OpalCrypto.Key.ExtendedPrivate.Error.depthOverflow:
            OpalDiagnostics.ErrorCode.depthOverflow
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidDerivedKey:
            OpalDiagnostics.ErrorCode.invalidDerivedKey

        case OpalCrypto.Key.ExtendedPublic.Error.invalidBase58:
            OpalDiagnostics.ErrorCode.invalidBase58
        case OpalCrypto.Key.ExtendedPublic.Error.invalidChecksum:
            OpalDiagnostics.ErrorCode.invalidChecksum
        case OpalCrypto.Key.ExtendedPublic.Error.invalidVersion:
            OpalDiagnostics.ErrorCode.invalidVersion
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPayloadLength:
            OpalDiagnostics.ErrorCode.invalidPayloadLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidParentFingerprintLength:
            OpalDiagnostics.ErrorCode.invalidParentFingerprintLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidChainCodeLength:
            OpalDiagnostics.ErrorCode.invalidChainCodeLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey
        case OpalCrypto.Key.ExtendedPublic.Error.invalidDepthMetadata:
            OpalDiagnostics.ErrorCode.invalidDepthMetadata
        case OpalCrypto.Key.ExtendedPublic.Error.hardenedDerivationRequiresPrivateKey:
            OpalDiagnostics.ErrorCode.hardenedDerivationRequiresPrivateKey
        case OpalCrypto.Key.ExtendedPublic.Error.depthOverflow:
            OpalDiagnostics.ErrorCode.depthOverflow
        case OpalCrypto.Key.ExtendedPublic.Error.invalidDerivedKey:
            OpalDiagnostics.ErrorCode.invalidDerivedKey

        case OpalCrypto.Communication.Error.messageTooLong:
            OpalDiagnostics.ErrorCode.messageTooLong
        case OpalCrypto.Communication.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.Communication.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.Communication.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey
        case OpalCrypto.Communication.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.Communication.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey
        case OpalCrypto.Communication.Error.invalidSymmetricKeyLength:
            OpalDiagnostics.ErrorCode.invalidSymmetricKeyLength
        case OpalCrypto.Communication.Error.invalidPaddedPlaintextLength:
            OpalDiagnostics.ErrorCode.invalidPaddedPlaintextLength
        case OpalCrypto.Communication.Error.paddedPlaintextLengthMustBeMultipleOf16:
            OpalDiagnostics.ErrorCode.paddedPlaintextLengthMustBeMultipleOf16
        case OpalCrypto.Communication.Error.invalidCiphertext:
            OpalDiagnostics.ErrorCode.invalidCiphertext
        case OpalCrypto.Communication.Error.cryptographyFailure:
            OpalDiagnostics.ErrorCode.cryptographyFailure

        case OpalCrypto.Encoding.Error.invalidFiveBitValue:
            OpalDiagnostics.ErrorCode.invalidFiveBitValue
        case OpalCrypto.Encoding.Error.invalidCharacterFound:
            OpalDiagnostics.ErrorCode.invalidCharacterFound

        case OpalCrypto.Pedersen.Error.invalidAlternateBasePointLength:
            OpalDiagnostics.ErrorCode.invalidAlternateBasePointLength
        case OpalCrypto.Pedersen.Error.invalidAlternateBasePointPrefix:
            OpalDiagnostics.ErrorCode.invalidAlternateBasePointPrefix
        case OpalCrypto.Pedersen.Error.invalidAlternateBasePoint:
            OpalDiagnostics.ErrorCode.invalidAlternateBasePoint
        case OpalCrypto.Pedersen.Error.insecureAlternateBasePoint:
            OpalDiagnostics.ErrorCode.insecureAlternateBasePoint
        case OpalCrypto.Pedersen.Error.invalidNonceLength:
            OpalDiagnostics.ErrorCode.invalidNonceLength
        case OpalCrypto.Pedersen.Error.invalidNonce:
            OpalDiagnostics.ErrorCode.invalidNonce
        case OpalCrypto.Pedersen.Error.invalidCommitmentLength:
            OpalDiagnostics.ErrorCode.invalidCommitmentLength
        case OpalCrypto.Pedersen.Error.invalidCommitment:
            OpalDiagnostics.ErrorCode.invalidCommitment
        case OpalCrypto.Pedersen.Error.emptyCommitmentList:
            OpalDiagnostics.ErrorCode.emptyCommitmentList
        case OpalCrypto.Pedersen.Error.mismatchedSetup:
            OpalDiagnostics.ErrorCode.mismatchedSetup
        case OpalCrypto.Pedersen.Error.cryptographyFailure:
            OpalDiagnostics.ErrorCode.cryptographyFailure

        case OpalCrypto.BlindSignature.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.BlindSignature.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.BlindSignature.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey
        case OpalCrypto.BlindSignature.Error.invalidNoncePointLength:
            OpalDiagnostics.ErrorCode.invalidNoncePointLength
        case OpalCrypto.BlindSignature.Error.invalidNoncePointPrefix:
            OpalDiagnostics.ErrorCode.invalidNoncePointPrefix
        case OpalCrypto.BlindSignature.Error.invalidNoncePoint:
            OpalDiagnostics.ErrorCode.invalidNoncePoint
        case OpalCrypto.BlindSignature.Error.invalidDigestLength:
            OpalDiagnostics.ErrorCode.invalidDigestLength
        case OpalCrypto.BlindSignature.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.BlindSignature.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey
        case OpalCrypto.BlindSignature.Error.invalidRequestLength:
            OpalDiagnostics.ErrorCode.invalidRequestLength
        case OpalCrypto.BlindSignature.Error.invalidRequestScalar:
            OpalDiagnostics.ErrorCode.invalidRequestScalar
        case OpalCrypto.BlindSignature.Error.invalidResponseLength:
            OpalDiagnostics.ErrorCode.invalidResponseLength
        case OpalCrypto.BlindSignature.Error.invalidResponseScalar:
            OpalDiagnostics.ErrorCode.invalidResponseScalar
        case OpalCrypto.BlindSignature.Error.nonceAlreadyUsed:
            OpalDiagnostics.ErrorCode.nonceAlreadyUsed
        case OpalCrypto.BlindSignature.Error.cryptographyFailure:
            OpalDiagnostics.ErrorCode.cryptographyFailure
        case OpalCrypto.BlindSignature.Error.verificationFailed:
            OpalDiagnostics.ErrorCode.verificationFailed

        case Base32EncodingCodec.Error.invalidFiveBitValue:
            OpalDiagnostics.ErrorCode.invalidFiveBitValue
        case Base32EncodingCodec.Error.invalidCharacterFound:
            OpalDiagnostics.ErrorCode.invalidCharacterFound
        case Base58CheckCodec.Error.invalidBase58:
            OpalDiagnostics.ErrorCode.invalidBase58
        case Base58CheckCodec.Error.invalidChecksum:
            OpalDiagnostics.ErrorCode.invalidChecksum
        case Base58CheckCodec.Error.invalidPayloadLength:
            OpalDiagnostics.ErrorCode.invalidPayloadLength
        case PasswordBasedKeyDerivationFunction2Model.Error.invalidIterationCount:
            OpalDiagnostics.ErrorCode.invalidIterationCount
        case PasswordBasedKeyDerivationFunction2Model.Error.emptySalt:
            OpalDiagnostics.ErrorCode.emptySalt
        case PasswordBasedKeyDerivationFunction2Model.Error.invalidDerivedKeyLength:
            OpalDiagnostics.ErrorCode.invalidDerivedKeyLength
        case PasswordBasedKeyDerivationFunction2Model.Error.keyLengthExceedsLimit:
            OpalDiagnostics.ErrorCode.derivedKeyLengthExceedsLimit

        default:
            OpalDiagnostics.ErrorCode(rawValue: String(reflecting: Swift.type(of: error)))
        }
    }
}

private extension OpalDiagnostics.ErrorCode {
    static let ambiguousLanguage = Self(rawValue: "ambiguous_language")
    static let cryptographyFailure = Self(rawValue: "cryptography_failure")
    static let derivedKeyLengthExceedsLimit = Self(rawValue: "derived_key_length_exceeds_limit")
    static let depthOverflow = Self(rawValue: "depth_overflow")
    static let emptyCommitmentList = Self(rawValue: "empty_commitment_list")
    static let emptySalt = Self(rawValue: "empty_salt")
    static let hardenedDerivationRequiresPrivateKey = Self(rawValue: "hardened_derivation_requires_private_key")
    static let insecureAlternateBasePoint = Self(rawValue: "insecure_alternate_base_point")
    static let invalidAlternateBasePoint = Self(rawValue: "invalid_alternate_base_point")
    static let invalidAlternateBasePointLength = Self(rawValue: "invalid_alternate_base_point_length")
    static let invalidAlternateBasePointPrefix = Self(rawValue: "invalid_alternate_base_point_prefix")
    static let invalidBase58 = Self(rawValue: "invalid_base58")
    static let invalidChainCodeLength = Self(rawValue: "invalid_chain_code_length")
    static let invalidCharacterFound = Self(rawValue: "invalid_character_found")
    static let invalidChecksum = Self(rawValue: "invalid_checksum")
    static let invalidCiphertext = Self(rawValue: "invalid_ciphertext")
    static let invalidCommitment = Self(rawValue: "invalid_commitment")
    static let invalidCommitmentLength = Self(rawValue: "invalid_commitment_length")
    static let invalidCompressionMarker = Self(rawValue: "invalid_compression_marker")
    static let invalidDerivedKey = Self(rawValue: "invalid_derived_key")
    static let invalidDerivedKeyLength = Self(rawValue: "invalid_derived_key_length")
    static let invalidDepthMetadata = Self(rawValue: "invalid_depth_metadata")
    static let invalidDigestLength = Self(rawValue: "invalid_digest_length")
    static let invalidDER = Self(rawValue: "invalid_der")
    static let invalidEntropyLength = Self(rawValue: "invalid_entropy_length")
    static let invalidFiveBitValue = Self(rawValue: "invalid_five_bit_value")
    static let invalidIterationCount = Self(rawValue: "invalid_iteration_count")
    static let invalidNonce = Self(rawValue: "invalid_nonce")
    static let invalidNonceLength = Self(rawValue: "invalid_nonce_length")
    static let invalidNoncePoint = Self(rawValue: "invalid_nonce_point")
    static let invalidNoncePointLength = Self(rawValue: "invalid_nonce_point_length")
    static let invalidNoncePointPrefix = Self(rawValue: "invalid_nonce_point_prefix")
    static let invalidPaddedPlaintextLength = Self(rawValue: "invalid_padded_plaintext_length")
    static let invalidParentFingerprintLength = Self(rawValue: "invalid_parent_fingerprint_length")
    static let invalidPayloadLength = Self(rawValue: "invalid_payload_length")
    static let invalidPrivateKey = Self(rawValue: "invalid_private_key")
    static let invalidPrivateKeyLength = Self(rawValue: "invalid_private_key_length")
    static let invalidPublicKey = Self(rawValue: "invalid_public_key")
    static let invalidPublicKeyLength = Self(rawValue: "invalid_public_key_length")
    static let invalidPublicKeyPrefix = Self(rawValue: "invalid_public_key_prefix")
    static let invalidRequestLength = Self(rawValue: "invalid_request_length")
    static let invalidRequestScalar = Self(rawValue: "invalid_request_scalar")
    static let invalidResponseLength = Self(rawValue: "invalid_response_length")
    static let invalidResponseScalar = Self(rawValue: "invalid_response_scalar")
    static let invalidSeedLength = Self(rawValue: "invalid_seed_length")
    static let invalidSignature = Self(rawValue: "invalid_signature")
    static let invalidSignatureLength = Self(rawValue: "invalid_signature_length")
    static let invalidSymmetricKeyLength = Self(rawValue: "invalid_symmetric_key_length")
    static let invalidTweak = Self(rawValue: "invalid_tweak")
    static let invalidTweakLength = Self(rawValue: "invalid_tweak_length")
    static let invalidVersion = Self(rawValue: "invalid_version")
    static let invalidWord = Self(rawValue: "invalid_word")
    static let invalidWordCount = Self(rawValue: "invalid_word_count")
    static let invalidWordList = Self(rawValue: "invalid_word_list")
    static let messageTooLong = Self(rawValue: "message_too_long")
    static let mismatchedSetup = Self(rawValue: "mismatched_setup")
    static let nonceAlreadyUsed = Self(rawValue: "nonce_already_used")
    static let nonCanonicalDER = Self(rawValue: "non_canonical_der")
    static let paddedPlaintextLengthMustBeMultipleOf16 = Self(rawValue: "padded_plaintext_length_must_be_multiple_of_16")
    static let randomGenerationFailed = Self(rawValue: "random_generation_failed")
    static let verificationFailed = Self(rawValue: "verification_failed")
    static let wordListResourceMissing = Self(rawValue: "word_list_resource_missing")
}
