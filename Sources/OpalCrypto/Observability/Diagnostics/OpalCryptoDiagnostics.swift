// OpalCryptoDiagnostics.swift

import Foundation
import OpalDiagnostics

enum OpalCryptoDiagnostics {
    typealias Field = OpalDiagnostics.Field

    enum Category {
        static let crypto = OpalCrypto.Diagnostics.Categories.crypto
        static let signature = OpalCrypto.Diagnostics.Categories.signature
        static let key = OpalCrypto.Diagnostics.Categories.key
        static let keyDerivation = OpalCrypto.Diagnostics.Categories.keyDerivation
        static let encoding = OpalCrypto.Diagnostics.Categories.encoding
        static let communication = OpalCrypto.Diagnostics.Categories.communication
        static let blindSignature = OpalCrypto.Diagnostics.Categories.blindSignature
        static let pedersen = OpalCrypto.Diagnostics.Categories.pedersen
        static let hashing = OpalCrypto.Diagnostics.Categories.hashing
    }

    enum Event {
        static let ecdsaSignBegin = OpalCrypto.Diagnostics.Events.ecdsaSignBegin
        static let ecdsaSignSucceeded = OpalCrypto.Diagnostics.Events.ecdsaSignSucceeded
        static let ecdsaSignFailed = OpalCrypto.Diagnostics.Events.ecdsaSignFailed
        static let ecdsaVerifyBegin = OpalCrypto.Diagnostics.Events.ecdsaVerifyBegin
        static let ecdsaVerifySucceeded = OpalCrypto.Diagnostics.Events.ecdsaVerifySucceeded
        static let ecdsaVerifyFailed = OpalCrypto.Diagnostics.Events.ecdsaVerifyFailed
        static let schnorrSignBegin = OpalCrypto.Diagnostics.Events.schnorrSignBegin
        static let schnorrSignSucceeded = OpalCrypto.Diagnostics.Events.schnorrSignSucceeded
        static let schnorrSignFailed = OpalCrypto.Diagnostics.Events.schnorrSignFailed
        static let schnorrVerifyBegin = OpalCrypto.Diagnostics.Events.schnorrVerifyBegin
        static let schnorrVerifySucceeded = OpalCrypto.Diagnostics.Events.schnorrVerifySucceeded
        static let schnorrVerifyFailed = OpalCrypto.Diagnostics.Events.schnorrVerifyFailed
        static let verificationKeyDeriveSucceeded = OpalCrypto.Diagnostics.Events.verificationKeyDeriveSucceeded
        static let verificationKeyDeriveFailed = OpalCrypto.Diagnostics.Events.verificationKeyDeriveFailed
        static let verificationKeyParseSucceeded = OpalCrypto.Diagnostics.Events.verificationKeyParseSucceeded
        static let verificationKeyParseFailed = OpalCrypto.Diagnostics.Events.verificationKeyParseFailed

        static let privateKeyGenerateSucceeded = OpalCrypto.Diagnostics.Events.privateKeyGenerateSucceeded
        static let privateKeyGenerateFailed = OpalCrypto.Diagnostics.Events.privateKeyGenerateFailed
        static let privateKeyParseSucceeded = OpalCrypto.Diagnostics.Events.privateKeyParseSucceeded
        static let privateKeyParseFailed = OpalCrypto.Diagnostics.Events.privateKeyParseFailed
        static let privateKeyTweakAddSucceeded = OpalCrypto.Diagnostics.Events.privateKeyTweakAddSucceeded
        static let privateKeyTweakAddFailed = OpalCrypto.Diagnostics.Events.privateKeyTweakAddFailed
        static let publicKeyParseSucceeded = OpalCrypto.Diagnostics.Events.publicKeyParseSucceeded
        static let publicKeyParseFailed = OpalCrypto.Diagnostics.Events.publicKeyParseFailed
        static let publicKeyDeriveSucceeded = OpalCrypto.Diagnostics.Events.publicKeyDeriveSucceeded
        static let publicKeyDeriveFailed = OpalCrypto.Diagnostics.Events.publicKeyDeriveFailed
        static let publicKeysDeriveSucceeded = OpalCrypto.Diagnostics.Events.publicKeysDeriveSucceeded
        static let publicKeysDeriveFailed = OpalCrypto.Diagnostics.Events.publicKeysDeriveFailed
        static let publicKeyTweakAddSucceeded = OpalCrypto.Diagnostics.Events.publicKeyTweakAddSucceeded
        static let publicKeyTweakAddFailed = OpalCrypto.Diagnostics.Events.publicKeyTweakAddFailed
        static let sharedSecretDeriveSucceeded = OpalCrypto.Diagnostics.Events.sharedSecretDeriveSucceeded
        static let sharedSecretDeriveFailed = OpalCrypto.Diagnostics.Events.sharedSecretDeriveFailed
        static let sharedSecretParseSucceeded = OpalCrypto.Diagnostics.Events.sharedSecretParseSucceeded
        static let sharedSecretParseFailed = OpalCrypto.Diagnostics.Events.sharedSecretParseFailed
        static let wifParseSucceeded = OpalCrypto.Diagnostics.Events.wifParseSucceeded
        static let wifParseFailed = OpalCrypto.Diagnostics.Events.wifParseFailed
        static let wifSerializeSucceeded = OpalCrypto.Diagnostics.Events.wifSerializeSucceeded
        static let wifSerializeFailed = OpalCrypto.Diagnostics.Events.wifSerializeFailed
        static let mnemonicParseSucceeded = OpalCrypto.Diagnostics.Events.mnemonicParseSucceeded
        static let mnemonicParseFailed = OpalCrypto.Diagnostics.Events.mnemonicParseFailed
        static let mnemonicGenerateSucceeded = OpalCrypto.Diagnostics.Events.mnemonicGenerateSucceeded
        static let mnemonicGenerateFailed = OpalCrypto.Diagnostics.Events.mnemonicGenerateFailed
        static let mnemonicSeedDeriveSucceeded = OpalCrypto.Diagnostics.Events.mnemonicSeedDeriveSucceeded
        static let mnemonicSeedDeriveFailed = OpalCrypto.Diagnostics.Events.mnemonicSeedDeriveFailed
        static let extendedPrivateParseSucceeded = OpalCrypto.Diagnostics.Events.extendedPrivateParseSucceeded
        static let extendedPrivateParseFailed = OpalCrypto.Diagnostics.Events.extendedPrivateParseFailed
        static let extendedPrivateRootSucceeded = OpalCrypto.Diagnostics.Events.extendedPrivateRootSucceeded
        static let extendedPrivateRootFailed = OpalCrypto.Diagnostics.Events.extendedPrivateRootFailed
        static let extendedPublicParseSucceeded = OpalCrypto.Diagnostics.Events.extendedPublicParseSucceeded
        static let extendedPublicParseFailed = OpalCrypto.Diagnostics.Events.extendedPublicParseFailed

        static let pbkdf2DeriveSucceeded = OpalCrypto.Diagnostics.Events.pbkdf2DeriveSucceeded
        static let pbkdf2DeriveFailed = OpalCrypto.Diagnostics.Events.pbkdf2DeriveFailed

        static let communicationEncryptBegin = OpalCrypto.Diagnostics.Events.communicationEncryptBegin
        static let communicationEncryptSucceeded = OpalCrypto.Diagnostics.Events.communicationEncryptSucceeded
        static let communicationEncryptFailed = OpalCrypto.Diagnostics.Events.communicationEncryptFailed
        static let communicationDecryptBegin = OpalCrypto.Diagnostics.Events.communicationDecryptBegin
        static let communicationDecryptSucceeded = OpalCrypto.Diagnostics.Events.communicationDecryptSucceeded
        static let communicationDecryptFailed = OpalCrypto.Diagnostics.Events.communicationDecryptFailed
        static let communicationCiphertextParseSucceeded = OpalCrypto.Diagnostics.Events.communicationCiphertextParseSucceeded
        static let communicationCiphertextParseFailed = OpalCrypto.Diagnostics.Events.communicationCiphertextParseFailed
        static let communicationSymmetricKeyParseSucceeded = OpalCrypto.Diagnostics.Events.communicationSymmetricKeyParseSucceeded
        static let communicationSymmetricKeyParseFailed = OpalCrypto.Diagnostics.Events.communicationSymmetricKeyParseFailed

        static let blindSignatureRequestBegin = OpalCrypto.Diagnostics.Events.blindSignatureRequestBegin
        static let blindSignatureRequestSucceeded = OpalCrypto.Diagnostics.Events.blindSignatureRequestSucceeded
        static let blindSignatureRequestFailed = OpalCrypto.Diagnostics.Events.blindSignatureRequestFailed
        static let blindSignatureSignerPrepareSucceeded = OpalCrypto.Diagnostics.Events.blindSignatureSignerPrepareSucceeded
        static let blindSignatureSignerPrepareFailed = OpalCrypto.Diagnostics.Events.blindSignatureSignerPrepareFailed
        static let blindSignatureSignBegin = OpalCrypto.Diagnostics.Events.blindSignatureSignBegin
        static let blindSignatureSignSucceeded = OpalCrypto.Diagnostics.Events.blindSignatureSignSucceeded
        static let blindSignatureSignFailed = OpalCrypto.Diagnostics.Events.blindSignatureSignFailed
        static let blindSignatureUnblindBegin = OpalCrypto.Diagnostics.Events.blindSignatureUnblindBegin
        static let blindSignatureUnblindSucceeded = OpalCrypto.Diagnostics.Events.blindSignatureUnblindSucceeded
        static let blindSignatureUnblindFailed = OpalCrypto.Diagnostics.Events.blindSignatureUnblindFailed
        static let blindSignatureVerifySucceeded = OpalCrypto.Diagnostics.Events.blindSignatureVerifySucceeded
        static let blindSignatureVerifyFailed = OpalCrypto.Diagnostics.Events.blindSignatureVerifyFailed

        static let pedersenSetupSucceeded = OpalCrypto.Diagnostics.Events.pedersenSetupSucceeded
        static let pedersenSetupFailed = OpalCrypto.Diagnostics.Events.pedersenSetupFailed
        static let pedersenCommitSucceeded = OpalCrypto.Diagnostics.Events.pedersenCommitSucceeded
        static let pedersenCommitFailed = OpalCrypto.Diagnostics.Events.pedersenCommitFailed
        static let pedersenVerifySucceeded = OpalCrypto.Diagnostics.Events.pedersenVerifySucceeded
        static let pedersenVerifyFailed = OpalCrypto.Diagnostics.Events.pedersenVerifyFailed
        static let pedersenCombineSucceeded = OpalCrypto.Diagnostics.Events.pedersenCombineSucceeded
        static let pedersenCombineFailed = OpalCrypto.Diagnostics.Events.pedersenCombineFailed
        static let pedersenCommitmentParseSucceeded = OpalCrypto.Diagnostics.Events.pedersenCommitmentParseSucceeded
        static let pedersenCommitmentParseFailed = OpalCrypto.Diagnostics.Events.pedersenCommitmentParseFailed
        static let pedersenNonceParseSucceeded = OpalCrypto.Diagnostics.Events.pedersenNonceParseSucceeded
        static let pedersenNonceParseFailed = OpalCrypto.Diagnostics.Events.pedersenNonceParseFailed

        static let sha256Succeeded = OpalCrypto.Diagnostics.Events.sha256Succeeded
        static let hash256Succeeded = OpalCrypto.Diagnostics.Events.hash256Succeeded
        static let hash160Succeeded = OpalCrypto.Diagnostics.Events.hash160Succeeded
        static let hmacSHA512Succeeded = OpalCrypto.Diagnostics.Events.hmacSHA512Succeeded
        static let hmacSHA256Succeeded = OpalCrypto.Diagnostics.Events.hmacSHA256Succeeded

        static let base58DecodeFailed = OpalCrypto.Diagnostics.Events.base58DecodeFailed
        static let base58CheckDecodeFailed = OpalCrypto.Diagnostics.Events.base58CheckDecodeFailed
        static let base32DecodeFailed = OpalCrypto.Diagnostics.Events.base32DecodeFailed
    }

    static func record(
        _ event: OpalDiagnostics.Event,
        category: OpalDiagnostics.Category,
        level: OpalDiagnostics.Level? = nil,
        traceID: OpalDiagnostics.TraceID? = nil,
        fields: [OpalDiagnostics.Field] = []
    ) {
        OpalDiagnostics.logger(category: category).record(
            event: event,
            level: level ?? defaultLevel(for: event),
            traceID: traceID,
            fields: fields
        )
    }

    static func publicField(_ name: String, _ value: String) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, publicValue: value)
    }

    static func publicField(_ name: String, _ value: Int) -> OpalDiagnostics.Field {
        OpalDiagnostics.Field(name: name, value: value)
    }

    static func publicField(_ name: String, _ value: UInt64) -> OpalDiagnostics.Field {
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

    private static func defaultLevel(for event: OpalDiagnostics.Event) -> OpalDiagnostics.Level {
        event.rawValue.hasSuffix(".failed") ? .error : .debug
    }

    private static func errorCode(for error: Swift.Error) -> String {
        switch error {
        case OpalCrypto.Secp256k1.Error.invalidPrivateKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.Secp256k1.Error.invalidPrivateKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKey
        case OpalCrypto.Secp256k1.Error.invalidPublicKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyLength
        case OpalCrypto.Secp256k1.Error.invalidPublicKeyPrefix:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.Secp256k1.Error.invalidPublicKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKey
        case OpalCrypto.Secp256k1.Error.invalidTweakLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidTweakLength
        case OpalCrypto.Secp256k1.Error.invalidTweak:
            OpalCrypto.Diagnostics.ErrorCodes.invalidTweak
        case OpalCrypto.Secp256k1.Error.invalidDerivedKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidDerivedKey
        case OpalCrypto.Secp256k1.Error.invalidSignatureLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidSignatureLength
        case OpalCrypto.Secp256k1.Error.invalidSignature:
            OpalCrypto.Diagnostics.ErrorCodes.invalidSignature
        case OpalCrypto.Secp256k1.Error.invalidDER:
            OpalCrypto.Diagnostics.ErrorCodes.invalidSignature
        case OpalCrypto.Secp256k1.Error.nonCanonicalDER:
            OpalCrypto.Diagnostics.ErrorCodes.nonCanonicalDER
        case OpalCrypto.Secp256k1.Error.randomGenerationFailed:
            OpalCrypto.Diagnostics.ErrorCodes.randomGenerationFailed

        case OpalCrypto.Signature.Error.invalidPrivateKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.Signature.Error.invalidPrivateKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKey
        case OpalCrypto.Signature.Error.invalidPublicKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyLength
        case OpalCrypto.Signature.Error.invalidPublicKeyPrefix:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.Signature.Error.invalidPublicKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKey
        case OpalCrypto.Signature.Error.invalidDigestLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidDigestLength
        case OpalCrypto.Signature.Error.invalidSignatureLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidSignatureLength
        case OpalCrypto.Signature.Error.invalidSignature:
            OpalCrypto.Diagnostics.ErrorCodes.invalidSignature
        case OpalCrypto.Signature.Error.invalidDER:
            OpalCrypto.Diagnostics.ErrorCodes.invalidSignature
        case OpalCrypto.Signature.Error.nonCanonicalDER:
            OpalCrypto.Diagnostics.ErrorCodes.nonCanonicalDER
        case OpalCrypto.Signature.Error.cryptographyFailure:
            OpalCrypto.Diagnostics.ErrorCodes.cryptographyFailure

        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyLength
        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKeyPrefix:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.Signature.VerificationKey.Error.invalidPublicKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKey

        case OpalCrypto.KeyDerivation.Error.invalidIterationCount:
            OpalCrypto.Diagnostics.ErrorCodes.invalidIterationCount
        case OpalCrypto.KeyDerivation.Error.emptySalt:
            OpalCrypto.Diagnostics.ErrorCodes.emptySalt
        case OpalCrypto.KeyDerivation.Error.invalidDerivedKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidDerivedKeyLength
        case OpalCrypto.KeyDerivation.Error.derivedKeyLengthExceedsLimit:
            OpalCrypto.Diagnostics.ErrorCodes.derivedKeyLengthExceedsLimit

        case OpalCrypto.Key.Mnemonic.Error.invalidWordCount:
            OpalCrypto.Diagnostics.ErrorCodes.invalidWordCount
        case OpalCrypto.Key.Mnemonic.Error.invalidEntropyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidEntropyLength
        case OpalCrypto.Key.Mnemonic.Error.invalidWord:
            OpalCrypto.Diagnostics.ErrorCodes.invalidWord
        case OpalCrypto.Key.Mnemonic.Error.invalidChecksum:
            OpalCrypto.Diagnostics.ErrorCodes.invalidChecksum
        case OpalCrypto.Key.Mnemonic.Error.ambiguousLanguage:
            OpalCrypto.Diagnostics.ErrorCodes.ambiguousLanguage
        case OpalCrypto.Key.Mnemonic.Error.randomGenerationFailed:
            OpalCrypto.Diagnostics.ErrorCodes.randomGenerationFailed
        case OpalCrypto.Key.Mnemonic.Error.wordListResourceMissing:
            OpalCrypto.Diagnostics.ErrorCodes.wordListResourceMissing
        case OpalCrypto.Key.Mnemonic.Error.invalidWordList:
            OpalCrypto.Diagnostics.ErrorCodes.invalidWordList

        case OpalCrypto.Key.WIF.Error.invalidBase58:
            OpalCrypto.Diagnostics.ErrorCodes.invalidBase58
        case OpalCrypto.Key.WIF.Error.invalidChecksum:
            OpalCrypto.Diagnostics.ErrorCodes.invalidChecksum
        case OpalCrypto.Key.WIF.Error.invalidPayloadLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPayloadLength
        case OpalCrypto.Key.WIF.Error.invalidVersion:
            OpalCrypto.Diagnostics.ErrorCodes.invalidVersion
        case OpalCrypto.Key.WIF.Error.invalidCompressionMarker:
            OpalCrypto.Diagnostics.ErrorCodes.invalidCompressionMarker
        case OpalCrypto.Key.WIF.Error.invalidPrivateKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.Key.WIF.Error.invalidPrivateKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKey

        case OpalCrypto.Key.ExtendedPrivate.Error.invalidBase58:
            OpalCrypto.Diagnostics.ErrorCodes.invalidBase58
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidChecksum:
            OpalCrypto.Diagnostics.ErrorCodes.invalidChecksum
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidVersion:
            OpalCrypto.Diagnostics.ErrorCodes.invalidVersion
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPayloadLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPayloadLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidParentFingerprintLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidParentFingerprintLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidChainCodeLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidChainCodeLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidSeedLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidSeedLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPrivateKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPrivateKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKey
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidDepthMetadata:
            OpalCrypto.Diagnostics.ErrorCodes.invalidDepthMetadata
        case OpalCrypto.Key.ExtendedPrivate.Error.depthOverflow:
            OpalCrypto.Diagnostics.ErrorCodes.depthOverflow
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidDerivedKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidDerivedKey

        case OpalCrypto.Key.ExtendedPublic.Error.invalidBase58:
            OpalCrypto.Diagnostics.ErrorCodes.invalidBase58
        case OpalCrypto.Key.ExtendedPublic.Error.invalidChecksum:
            OpalCrypto.Diagnostics.ErrorCodes.invalidChecksum
        case OpalCrypto.Key.ExtendedPublic.Error.invalidVersion:
            OpalCrypto.Diagnostics.ErrorCodes.invalidVersion
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPayloadLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPayloadLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidParentFingerprintLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidParentFingerprintLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidChainCodeLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidChainCodeLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKeyPrefix:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKey
        case OpalCrypto.Key.ExtendedPublic.Error.invalidDepthMetadata:
            OpalCrypto.Diagnostics.ErrorCodes.invalidDepthMetadata
        case OpalCrypto.Key.ExtendedPublic.Error.hardenedDerivationRequiresPrivateKey:
            OpalCrypto.Diagnostics.ErrorCodes.hardenedDerivationRequiresPrivateKey
        case OpalCrypto.Key.ExtendedPublic.Error.depthOverflow:
            OpalCrypto.Diagnostics.ErrorCodes.depthOverflow
        case OpalCrypto.Key.ExtendedPublic.Error.invalidDerivedKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidDerivedKey

        case OpalCrypto.Communication.Error.messageTooLong:
            OpalCrypto.Diagnostics.ErrorCodes.messageTooLong
        case OpalCrypto.Communication.Error.invalidPublicKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyLength
        case OpalCrypto.Communication.Error.invalidPublicKeyPrefix:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.Communication.Error.invalidPublicKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKey
        case OpalCrypto.Communication.Error.invalidPrivateKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.Communication.Error.invalidPrivateKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKey
        case OpalCrypto.Communication.Error.invalidSymmetricKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidSymmetricKeyLength
        case OpalCrypto.Communication.Error.invalidPaddedPlaintextLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPaddedPlaintextLength
        case OpalCrypto.Communication.Error.paddedPlaintextLengthMustBeMultipleOf16:
            OpalCrypto.Diagnostics.ErrorCodes.paddedPlaintextLengthMustBeMultipleOf16
        case OpalCrypto.Communication.Error.invalidCiphertext:
            OpalCrypto.Diagnostics.ErrorCodes.invalidCiphertext
        case OpalCrypto.Communication.Error.cryptographyFailure:
            OpalCrypto.Diagnostics.ErrorCodes.cryptographyFailure

        case OpalCrypto.Encoding.Error.invalidFiveBitValue:
            OpalCrypto.Diagnostics.ErrorCodes.invalidFiveBitValue
        case OpalCrypto.Encoding.Error.invalidCharacterFound:
            OpalCrypto.Diagnostics.ErrorCodes.invalidCharacterFound

        case OpalCrypto.Pedersen.Error.invalidAlternateBasePointLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidAlternateBasePointLength
        case OpalCrypto.Pedersen.Error.invalidAlternateBasePointPrefix:
            OpalCrypto.Diagnostics.ErrorCodes.invalidAlternateBasePointPrefix
        case OpalCrypto.Pedersen.Error.invalidAlternateBasePoint:
            OpalCrypto.Diagnostics.ErrorCodes.invalidAlternateBasePoint
        case OpalCrypto.Pedersen.Error.insecureAlternateBasePoint:
            OpalCrypto.Diagnostics.ErrorCodes.insecureAlternateBasePoint
        case OpalCrypto.Pedersen.Error.invalidNonceLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidNonceLength
        case OpalCrypto.Pedersen.Error.invalidNonce:
            OpalCrypto.Diagnostics.ErrorCodes.invalidNonce
        case OpalCrypto.Pedersen.Error.invalidCommitmentLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidCommitmentLength
        case OpalCrypto.Pedersen.Error.invalidCommitment:
            OpalCrypto.Diagnostics.ErrorCodes.invalidCommitment
        case OpalCrypto.Pedersen.Error.emptyCommitmentList:
            OpalCrypto.Diagnostics.ErrorCodes.emptyCommitmentList
        case OpalCrypto.Pedersen.Error.mismatchedSetup:
            OpalCrypto.Diagnostics.ErrorCodes.mismatchedSetup
        case OpalCrypto.Pedersen.Error.cryptographyFailure:
            OpalCrypto.Diagnostics.ErrorCodes.cryptographyFailure

        case OpalCrypto.BlindSignature.Error.invalidPublicKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyLength
        case OpalCrypto.BlindSignature.Error.invalidPublicKeyPrefix:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKeyPrefix
        case OpalCrypto.BlindSignature.Error.invalidPublicKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPublicKey
        case OpalCrypto.BlindSignature.Error.invalidNoncePointLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidNoncePointLength
        case OpalCrypto.BlindSignature.Error.invalidNoncePointPrefix:
            OpalCrypto.Diagnostics.ErrorCodes.invalidNoncePointPrefix
        case OpalCrypto.BlindSignature.Error.invalidNoncePoint:
            OpalCrypto.Diagnostics.ErrorCodes.invalidNoncePoint
        case OpalCrypto.BlindSignature.Error.invalidDigestLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidDigestLength
        case OpalCrypto.BlindSignature.Error.invalidPrivateKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKeyLength
        case OpalCrypto.BlindSignature.Error.invalidPrivateKey:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPrivateKey
        case OpalCrypto.BlindSignature.Error.invalidRequestLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidRequestLength
        case OpalCrypto.BlindSignature.Error.invalidRequestScalar:
            OpalCrypto.Diagnostics.ErrorCodes.invalidRequestScalar
        case OpalCrypto.BlindSignature.Error.invalidResponseLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidResponseLength
        case OpalCrypto.BlindSignature.Error.invalidResponseScalar:
            OpalCrypto.Diagnostics.ErrorCodes.invalidResponseScalar
        case OpalCrypto.BlindSignature.Error.nonceAlreadyUsed:
            OpalCrypto.Diagnostics.ErrorCodes.nonceAlreadyUsed
        case OpalCrypto.BlindSignature.Error.cryptographyFailure:
            OpalCrypto.Diagnostics.ErrorCodes.cryptographyFailure
        case OpalCrypto.BlindSignature.Error.verificationFailed:
            OpalCrypto.Diagnostics.ErrorCodes.verificationFailed

        case Base32EncodingModel.Error.invalidFiveBitValue:
            OpalCrypto.Diagnostics.ErrorCodes.invalidFiveBitValue
        case Base32EncodingModel.Error.invalidCharacterFound:
            OpalCrypto.Diagnostics.ErrorCodes.invalidCharacterFound
        case Base58CheckCodec.Error.invalidBase58:
            OpalCrypto.Diagnostics.ErrorCodes.invalidBase58
        case Base58CheckCodec.Error.invalidChecksum:
            OpalCrypto.Diagnostics.ErrorCodes.invalidChecksum
        case Base58CheckCodec.Error.invalidPayloadLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidPayloadLength
        case PasswordBasedKeyDerivationFunction2Model.Error.invalidIterationCount:
            OpalCrypto.Diagnostics.ErrorCodes.invalidIterationCount
        case PasswordBasedKeyDerivationFunction2Model.Error.emptySalt:
            OpalCrypto.Diagnostics.ErrorCodes.emptySalt
        case PasswordBasedKeyDerivationFunction2Model.Error.invalidDerivedKeyLength:
            OpalCrypto.Diagnostics.ErrorCodes.invalidDerivedKeyLength
        case PasswordBasedKeyDerivationFunction2Model.Error.keyLengthExceedsLimit:
            OpalCrypto.Diagnostics.ErrorCodes.derivedKeyLengthExceedsLimit

        default:
            String(reflecting: Swift.type(of: error))
        }
    }
}
