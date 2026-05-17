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
            publicField("error_code", errorCode(for: error)),
            publicField("error_type", String(reflecting: Swift.type(of: error))),
            privateField("error_message", String(describing: error))
        ]
    }

    private static func errorCode(for error: Swift.Error) -> String {
        switch error {
        case OpalCrypto.Secp256k1.Error.invalidPrivateKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.Secp256k1.Error.invalidPrivateKey:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKey
        case OpalCrypto.Secp256k1.Error.invalidPublicKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyLength
        case OpalCrypto.Secp256k1.Error.invalidPublicKeyPrefix:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.Secp256k1.Error.invalidPublicKey:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKey
        case OpalCrypto.Secp256k1.Error.invalidTweakLength:
            OpalCryptoDiagnosticErrorCodes.invalidTweakLength
        case OpalCrypto.Secp256k1.Error.invalidTweak:
            OpalCryptoDiagnosticErrorCodes.invalidTweak
        case OpalCrypto.Secp256k1.Error.invalidDerivedKey:
            OpalCryptoDiagnosticErrorCodes.invalidDerivedKey
        case OpalCrypto.Secp256k1.Error.invalidSignatureLength:
            OpalCryptoDiagnosticErrorCodes.invalidSignatureLength
        case OpalCrypto.Secp256k1.Error.invalidSignature:
            OpalCryptoDiagnosticErrorCodes.invalidSignature
        case OpalCrypto.Secp256k1.Error.invalidDER:
            OpalCryptoDiagnosticErrorCodes.invalidDER
        case OpalCrypto.Secp256k1.Error.nonCanonicalDER:
            OpalCryptoDiagnosticErrorCodes.nonCanonicalDER
        case OpalCrypto.Secp256k1.Error.randomGenerationFailed:
            OpalCryptoDiagnosticErrorCodes.randomGenerationFailed

        case OpalCrypto.Signature.Error.invalidPrivateKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.Signature.Error.invalidPrivateKey:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKey
        case OpalCrypto.Signature.Error.invalidPublicKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyLength
        case OpalCrypto.Signature.Error.invalidPublicKeyPrefix:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.Signature.Error.invalidPublicKey:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKey
        case OpalCrypto.Signature.Error.invalidDigestLength:
            OpalCryptoDiagnosticErrorCodes.invalidDigestLength
        case OpalCrypto.Signature.Error.invalidSignatureLength:
            OpalCryptoDiagnosticErrorCodes.invalidSignatureLength
        case OpalCrypto.Signature.Error.invalidSignature:
            OpalCryptoDiagnosticErrorCodes.invalidSignature
        case OpalCrypto.Signature.Error.invalidDER:
            OpalCryptoDiagnosticErrorCodes.invalidDER
        case OpalCrypto.Signature.Error.nonCanonicalDER:
            OpalCryptoDiagnosticErrorCodes.nonCanonicalDER
        case OpalCrypto.Signature.Error.cryptographyFailure:
            OpalCryptoDiagnosticErrorCodes.cryptographyFailure

        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyLength
        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKeyPrefix:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKey:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKey

        case OpalCrypto.KeyDerivation.Error.invalidIterationCount:
            OpalCryptoDiagnosticErrorCodes.invalidIterationCount
        case OpalCrypto.KeyDerivation.Error.emptySalt:
            OpalCryptoDiagnosticErrorCodes.emptySalt
        case OpalCrypto.KeyDerivation.Error.invalidDerivedKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidDerivedKeyLength
        case OpalCrypto.KeyDerivation.Error.derivedKeyLengthExceedsLimit:
            OpalCryptoDiagnosticErrorCodes.derivedKeyLengthExceedsLimit

        case OpalCrypto.Key.Mnemonic.Error.invalidWordCount:
            OpalCryptoDiagnosticErrorCodes.invalidWordCount
        case OpalCrypto.Key.Mnemonic.Error.invalidEntropyLength:
            OpalCryptoDiagnosticErrorCodes.invalidEntropyLength
        case OpalCrypto.Key.Mnemonic.Error.invalidWord:
            OpalCryptoDiagnosticErrorCodes.invalidWord
        case OpalCrypto.Key.Mnemonic.Error.invalidChecksum:
            OpalCryptoDiagnosticErrorCodes.invalidChecksum
        case OpalCrypto.Key.Mnemonic.Error.ambiguousLanguage:
            OpalCryptoDiagnosticErrorCodes.ambiguousLanguage
        case OpalCrypto.Key.Mnemonic.Error.randomGenerationFailed:
            OpalCryptoDiagnosticErrorCodes.randomGenerationFailed
        case OpalCrypto.Key.Mnemonic.Error.wordListResourceMissing:
            OpalCryptoDiagnosticErrorCodes.wordListResourceMissing
        case OpalCrypto.Key.Mnemonic.Error.invalidWordList:
            OpalCryptoDiagnosticErrorCodes.invalidWordList

        case OpalCrypto.Key.WIF.Error.invalidBase58:
            OpalCryptoDiagnosticErrorCodes.invalidBase58
        case OpalCrypto.Key.WIF.Error.invalidChecksum:
            OpalCryptoDiagnosticErrorCodes.invalidChecksum
        case OpalCrypto.Key.WIF.Error.invalidPayloadLength:
            OpalCryptoDiagnosticErrorCodes.invalidPayloadLength
        case OpalCrypto.Key.WIF.Error.invalidVersion:
            OpalCryptoDiagnosticErrorCodes.invalidVersion
        case OpalCrypto.Key.WIF.Error.invalidCompressionMarker:
            OpalCryptoDiagnosticErrorCodes.invalidCompressionMarker
        case OpalCrypto.Key.WIF.Error.invalidPrivateKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.Key.WIF.Error.invalidPrivateKey:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKey

        case OpalCrypto.Key.ExtendedPrivate.Error.invalidBase58:
            OpalCryptoDiagnosticErrorCodes.invalidBase58
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidChecksum:
            OpalCryptoDiagnosticErrorCodes.invalidChecksum
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidVersion:
            OpalCryptoDiagnosticErrorCodes.invalidVersion
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPayloadLength:
            OpalCryptoDiagnosticErrorCodes.invalidPayloadLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidParentFingerprintLength:
            OpalCryptoDiagnosticErrorCodes.invalidParentFingerprintLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidChainCodeLength:
            OpalCryptoDiagnosticErrorCodes.invalidChainCodeLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidSeedLength:
            OpalCryptoDiagnosticErrorCodes.invalidSeedLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPrivateKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPrivateKey:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKey
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidDepthMetadata:
            OpalCryptoDiagnosticErrorCodes.invalidDepthMetadata
        case OpalCrypto.Key.ExtendedPrivate.Error.depthOverflow:
            OpalCryptoDiagnosticErrorCodes.depthOverflow
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidDerivedKey:
            OpalCryptoDiagnosticErrorCodes.invalidDerivedKey

        case OpalCrypto.Key.ExtendedPublic.Error.invalidBase58:
            OpalCryptoDiagnosticErrorCodes.invalidBase58
        case OpalCrypto.Key.ExtendedPublic.Error.invalidChecksum:
            OpalCryptoDiagnosticErrorCodes.invalidChecksum
        case OpalCrypto.Key.ExtendedPublic.Error.invalidVersion:
            OpalCryptoDiagnosticErrorCodes.invalidVersion
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPayloadLength:
            OpalCryptoDiagnosticErrorCodes.invalidPayloadLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidParentFingerprintLength:
            OpalCryptoDiagnosticErrorCodes.invalidParentFingerprintLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidChainCodeLength:
            OpalCryptoDiagnosticErrorCodes.invalidChainCodeLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKeyPrefix:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKey:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKey
        case OpalCrypto.Key.ExtendedPublic.Error.invalidDepthMetadata:
            OpalCryptoDiagnosticErrorCodes.invalidDepthMetadata
        case OpalCrypto.Key.ExtendedPublic.Error.hardenedDerivationRequiresPrivateKey:
            OpalCryptoDiagnosticErrorCodes.hardenedDerivationRequiresPrivateKey
        case OpalCrypto.Key.ExtendedPublic.Error.depthOverflow:
            OpalCryptoDiagnosticErrorCodes.depthOverflow
        case OpalCrypto.Key.ExtendedPublic.Error.invalidDerivedKey:
            OpalCryptoDiagnosticErrorCodes.invalidDerivedKey

        case OpalCrypto.Communication.Error.messageTooLong:
            OpalCryptoDiagnosticErrorCodes.messageTooLong
        case OpalCrypto.Communication.Error.invalidPublicKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyLength
        case OpalCrypto.Communication.Error.invalidPublicKeyPrefix:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.Communication.Error.invalidPublicKey:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKey
        case OpalCrypto.Communication.Error.invalidPrivateKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.Communication.Error.invalidPrivateKey:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKey
        case OpalCrypto.Communication.Error.invalidSymmetricKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidSymmetricKeyLength
        case OpalCrypto.Communication.Error.invalidPaddedPlaintextLength:
            OpalCryptoDiagnosticErrorCodes.invalidPaddedPlaintextLength
        case OpalCrypto.Communication.Error.paddedPlaintextLengthMustBeMultipleOf16:
            OpalCryptoDiagnosticErrorCodes.paddedPlaintextLengthMustBeMultipleOf16
        case OpalCrypto.Communication.Error.invalidCiphertext:
            OpalCryptoDiagnosticErrorCodes.invalidCiphertext
        case OpalCrypto.Communication.Error.cryptographyFailure:
            OpalCryptoDiagnosticErrorCodes.cryptographyFailure

        case OpalCrypto.Encoding.Error.invalidFiveBitValue:
            OpalCryptoDiagnosticErrorCodes.invalidFiveBitValue
        case OpalCrypto.Encoding.Error.invalidCharacterFound:
            OpalCryptoDiagnosticErrorCodes.invalidCharacterFound

        case OpalCrypto.Pedersen.Error.invalidAlternateBasePointLength:
            OpalCryptoDiagnosticErrorCodes.invalidAlternateBasePointLength
        case OpalCrypto.Pedersen.Error.invalidAlternateBasePointPrefix:
            OpalCryptoDiagnosticErrorCodes.invalidAlternateBasePointPrefix
        case OpalCrypto.Pedersen.Error.invalidAlternateBasePoint:
            OpalCryptoDiagnosticErrorCodes.invalidAlternateBasePoint
        case OpalCrypto.Pedersen.Error.insecureAlternateBasePoint:
            OpalCryptoDiagnosticErrorCodes.insecureAlternateBasePoint
        case OpalCrypto.Pedersen.Error.invalidNonceLength:
            OpalCryptoDiagnosticErrorCodes.invalidNonceLength
        case OpalCrypto.Pedersen.Error.invalidNonce:
            OpalCryptoDiagnosticErrorCodes.invalidNonce
        case OpalCrypto.Pedersen.Error.invalidCommitmentLength:
            OpalCryptoDiagnosticErrorCodes.invalidCommitmentLength
        case OpalCrypto.Pedersen.Error.invalidCommitment:
            OpalCryptoDiagnosticErrorCodes.invalidCommitment
        case OpalCrypto.Pedersen.Error.emptyCommitmentList:
            OpalCryptoDiagnosticErrorCodes.emptyCommitmentList
        case OpalCrypto.Pedersen.Error.mismatchedSetup:
            OpalCryptoDiagnosticErrorCodes.mismatchedSetup
        case OpalCrypto.Pedersen.Error.cryptographyFailure:
            OpalCryptoDiagnosticErrorCodes.cryptographyFailure

        case OpalCrypto.BlindSignature.Error.invalidPublicKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyLength
        case OpalCrypto.BlindSignature.Error.invalidPublicKeyPrefix:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.BlindSignature.Error.invalidPublicKey:
            OpalCryptoDiagnosticErrorCodes.invalidPublicKey
        case OpalCrypto.BlindSignature.Error.invalidNoncePointLength:
            OpalCryptoDiagnosticErrorCodes.invalidNoncePointLength
        case OpalCrypto.BlindSignature.Error.invalidNoncePointPrefix:
            OpalCryptoDiagnosticErrorCodes.invalidNoncePointPrefix
        case OpalCrypto.BlindSignature.Error.invalidNoncePoint:
            OpalCryptoDiagnosticErrorCodes.invalidNoncePoint
        case OpalCrypto.BlindSignature.Error.invalidDigestLength:
            OpalCryptoDiagnosticErrorCodes.invalidDigestLength
        case OpalCrypto.BlindSignature.Error.invalidPrivateKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.BlindSignature.Error.invalidPrivateKey:
            OpalCryptoDiagnosticErrorCodes.invalidPrivateKey
        case OpalCrypto.BlindSignature.Error.invalidRequestLength:
            OpalCryptoDiagnosticErrorCodes.invalidRequestLength
        case OpalCrypto.BlindSignature.Error.invalidRequestScalar:
            OpalCryptoDiagnosticErrorCodes.invalidRequestScalar
        case OpalCrypto.BlindSignature.Error.invalidResponseLength:
            OpalCryptoDiagnosticErrorCodes.invalidResponseLength
        case OpalCrypto.BlindSignature.Error.invalidResponseScalar:
            OpalCryptoDiagnosticErrorCodes.invalidResponseScalar
        case OpalCrypto.BlindSignature.Error.nonceAlreadyUsed:
            OpalCryptoDiagnosticErrorCodes.nonceAlreadyUsed
        case OpalCrypto.BlindSignature.Error.cryptographyFailure:
            OpalCryptoDiagnosticErrorCodes.cryptographyFailure
        case OpalCrypto.BlindSignature.Error.verificationFailed:
            OpalCryptoDiagnosticErrorCodes.verificationFailed

        case Base32EncodingModel.Error.invalidFiveBitValue:
            OpalCryptoDiagnosticErrorCodes.invalidFiveBitValue
        case Base32EncodingModel.Error.invalidCharacterFound:
            OpalCryptoDiagnosticErrorCodes.invalidCharacterFound
        case Base58CheckCodec.Error.invalidBase58:
            OpalCryptoDiagnosticErrorCodes.invalidBase58
        case Base58CheckCodec.Error.invalidChecksum:
            OpalCryptoDiagnosticErrorCodes.invalidChecksum
        case Base58CheckCodec.Error.invalidPayloadLength:
            OpalCryptoDiagnosticErrorCodes.invalidPayloadLength
        case PasswordBasedKeyDerivationFunction2Model.Error.invalidIterationCount:
            OpalCryptoDiagnosticErrorCodes.invalidIterationCount
        case PasswordBasedKeyDerivationFunction2Model.Error.emptySalt:
            OpalCryptoDiagnosticErrorCodes.emptySalt
        case PasswordBasedKeyDerivationFunction2Model.Error.invalidDerivedKeyLength:
            OpalCryptoDiagnosticErrorCodes.invalidDerivedKeyLength
        case PasswordBasedKeyDerivationFunction2Model.Error.keyLengthExceedsLimit:
            OpalCryptoDiagnosticErrorCodes.derivedKeyLengthExceedsLimit

        default:
            String(reflecting: Swift.type(of: error))
        }
    }
}

private enum OpalCryptoDiagnosticErrorCodes {
    static let ambiguousLanguage = "ambiguous_language"
    static let cryptographyFailure = "cryptography_failure"
    static let derivedKeyLengthExceedsLimit = "derived_key_length_exceeds_limit"
    static let depthOverflow = "depth_overflow"
    static let emptyCommitmentList = "empty_commitment_list"
    static let emptySalt = "empty_salt"
    static let hardenedDerivationRequiresPrivateKey = "hardened_derivation_requires_private_key"
    static let insecureAlternateBasePoint = "insecure_alternate_base_point"
    static let invalidAlternateBasePoint = "invalid_alternate_base_point"
    static let invalidAlternateBasePointLength = "invalid_alternate_base_point_length"
    static let invalidAlternateBasePointPrefix = "invalid_alternate_base_point_prefix"
    static let invalidBase58 = "invalid_base58"
    static let invalidChainCodeLength = "invalid_chain_code_length"
    static let invalidCharacterFound = "invalid_character_found"
    static let invalidChecksum = "invalid_checksum"
    static let invalidCiphertext = "invalid_ciphertext"
    static let invalidCommitment = "invalid_commitment"
    static let invalidCommitmentLength = "invalid_commitment_length"
    static let invalidCompressionMarker = "invalid_compression_marker"
    static let invalidDerivedKey = "invalid_derived_key"
    static let invalidDerivedKeyLength = "invalid_derived_key_length"
    static let invalidDepthMetadata = "invalid_depth_metadata"
    static let invalidDigestLength = "invalid_digest_length"
    static let invalidDER = "invalid_der"
    static let invalidEntropyLength = "invalid_entropy_length"
    static let invalidFiveBitValue = "invalid_five_bit_value"
    static let invalidIterationCount = "invalid_iteration_count"
    static let invalidNonce = "invalid_nonce"
    static let invalidNonceLength = "invalid_nonce_length"
    static let invalidNoncePoint = "invalid_nonce_point"
    static let invalidNoncePointLength = "invalid_nonce_point_length"
    static let invalidNoncePointPrefix = "invalid_nonce_point_prefix"
    static let invalidPaddedPlaintextLength = "invalid_padded_plaintext_length"
    static let invalidParentFingerprintLength = "invalid_parent_fingerprint_length"
    static let invalidPayloadLength = "invalid_payload_length"
    static let invalidPrivateKey = "invalid_private_key"
    static let invalidPrivateKeyLength = "invalid_private_key_length"
    static let invalidPublicKey = "invalid_public_key"
    static let invalidPublicKeyLength = "invalid_public_key_length"
    static let invalidPublicKeyPrefix = "invalid_public_key_prefix"
    static let invalidRequestLength = "invalid_request_length"
    static let invalidRequestScalar = "invalid_request_scalar"
    static let invalidResponseLength = "invalid_response_length"
    static let invalidResponseScalar = "invalid_response_scalar"
    static let invalidSeedLength = "invalid_seed_length"
    static let invalidSignature = "invalid_signature"
    static let invalidSignatureLength = "invalid_signature_length"
    static let invalidSymmetricKeyLength = "invalid_symmetric_key_length"
    static let invalidTweak = "invalid_tweak"
    static let invalidTweakLength = "invalid_tweak_length"
    static let invalidVersion = "invalid_version"
    static let invalidWord = "invalid_word"
    static let invalidWordCount = "invalid_word_count"
    static let invalidWordList = "invalid_word_list"
    static let messageTooLong = "message_too_long"
    static let mismatchedSetup = "mismatched_setup"
    static let nonceAlreadyUsed = "nonce_already_used"
    static let nonCanonicalDER = "non_canonical_der"
    static let paddedPlaintextLengthMustBeMultipleOf16 = "padded_plaintext_length_must_be_multiple_of_16"
    static let randomGenerationFailed = "random_generation_failed"
    static let verificationFailed = "verification_failed"
    static let wordListResourceMissing = "word_list_resource_missing"
}
