// OpalCrypto+Diagnostics.swift

import Foundation
import OpalDiagnostics

public extension OpalCrypto {
    /// Stable diagnostics names and trace helpers for correlating OpalCrypto operations from application code.
    enum Diagnostics {
        public typealias Category = OpalDiagnostics.Category
        public typealias Event = OpalDiagnostics.Event
        public typealias Level = OpalDiagnostics.Level
        public typealias TraceID = OpalDiagnostics.TraceID

        public enum Categories {
            public static let crypto = OpalDiagnostics.Category.crypto
            public static let signature = OpalDiagnostics.Category(rawValue: "crypto.signature")
            public static let key = OpalDiagnostics.Category(rawValue: "crypto.key")
            public static let keyDerivation = OpalDiagnostics.Category(rawValue: "crypto.key_derivation")
            public static let encoding = OpalDiagnostics.Category(rawValue: "crypto.encoding")
            public static let communication = OpalDiagnostics.Category(rawValue: "crypto.communication")
            public static let blindSignature = OpalDiagnostics.Category(rawValue: "crypto.blind_signature")
            public static let pedersen = OpalDiagnostics.Category(rawValue: "crypto.pedersen")
            public static let hashing = OpalDiagnostics.Category(rawValue: "crypto.hashing")
        }

        public enum Events {
            public static let ecdsaSignBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.sign.begin")
            public static let ecdsaSignSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.sign.succeeded")
            public static let ecdsaSignFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.sign.failed")
            public static let ecdsaVerifyBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.verify.begin")
            public static let ecdsaVerifySucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.verify.succeeded")
            public static let ecdsaVerifyFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.ecdsa.verify.failed")
            public static let schnorrSignBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.sign.begin")
            public static let schnorrSignSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.sign.succeeded")
            public static let schnorrSignFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.sign.failed")
            public static let schnorrVerifyBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.verify.begin")
            public static let schnorrVerifySucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.verify.succeeded")
            public static let schnorrVerifyFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.schnorr.verify.failed")
            public static let verificationKeyDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.verification_key.derive.succeeded")
            public static let verificationKeyDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.verification_key.derive.failed")
            public static let verificationKeyParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.verification_key.parse.succeeded")
            public static let verificationKeyParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.signature.verification_key.parse.failed")

            public static let privateKeyGenerateSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.generate.succeeded")
            public static let privateKeyGenerateFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.generate.failed")
            public static let privateKeyParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.parse.succeeded")
            public static let privateKeyParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.parse.failed")
            public static let privateKeyTweakAddSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.tweak_add.succeeded")
            public static let privateKeyTweakAddFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.private.tweak_add.failed")
            public static let publicKeyParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.parse.succeeded")
            public static let publicKeyParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.parse.failed")
            public static let publicKeyDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.derive.succeeded")
            public static let publicKeyDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.derive.failed")
            public static let publicKeysDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.batch_derive.succeeded")
            public static let publicKeysDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.batch_derive.failed")
            public static let publicKeyTweakAddSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.tweak_add.succeeded")
            public static let publicKeyTweakAddFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.tweak_add.failed")
            public static let sharedSecretDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.shared_secret.derive.succeeded")
            public static let sharedSecretDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.shared_secret.derive.failed")
            public static let sharedSecretParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.shared_secret.parse.succeeded")
            public static let sharedSecretParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.shared_secret.parse.failed")
            public static let wifParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.parse.succeeded")
            public static let wifParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.parse.failed")
            public static let wifSerializeSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.serialize.succeeded")
            public static let wifSerializeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.serialize.failed")
            public static let mnemonicParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.parse.succeeded")
            public static let mnemonicParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.parse.failed")
            public static let mnemonicGenerateSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.generate.succeeded")
            public static let mnemonicGenerateFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.generate.failed")
            public static let mnemonicSeedDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.seed.derive.succeeded")
            public static let mnemonicSeedDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.seed.derive.failed")
            public static let extendedPrivateParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.parse.succeeded")
            public static let extendedPrivateParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.parse.failed")
            public static let extendedPrivateRootSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.root.succeeded")
            public static let extendedPrivateRootFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.root.failed")
            public static let extendedPublicParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_public.parse.succeeded")
            public static let extendedPublicParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_public.parse.failed")

            public static let pbkdf2DeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key_derivation.pbkdf2.derive.succeeded")
            public static let pbkdf2DeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key_derivation.pbkdf2.derive.failed")

            public static let communicationEncryptBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.encrypt.begin")
            public static let communicationEncryptSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.encrypt.succeeded")
            public static let communicationEncryptFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.encrypt.failed")
            public static let communicationDecryptBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.decrypt.begin")
            public static let communicationDecryptSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.decrypt.succeeded")
            public static let communicationDecryptFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.decrypt.failed")
            public static let communicationCiphertextParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.ciphertext.parse.succeeded")
            public static let communicationCiphertextParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.ciphertext.parse.failed")
            public static let communicationSymmetricKeyParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.symmetric_key.parse.succeeded")
            public static let communicationSymmetricKeyParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.communication.symmetric_key.parse.failed")

            public static let blindSignatureRequestBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.request.begin")
            public static let blindSignatureRequestSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.request.succeeded")
            public static let blindSignatureRequestFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.request.failed")
            public static let blindSignatureSignerPrepareSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.signer.prepare.succeeded")
            public static let blindSignatureSignerPrepareFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.signer.prepare.failed")
            public static let blindSignatureSignBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.sign.begin")
            public static let blindSignatureSignSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.sign.succeeded")
            public static let blindSignatureSignFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.sign.failed")
            public static let blindSignatureUnblindBegin = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.unblind.begin")
            public static let blindSignatureUnblindSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.unblind.succeeded")
            public static let blindSignatureUnblindFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.unblind.failed")
            public static let blindSignatureVerifySucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.verify.succeeded")
            public static let blindSignatureVerifyFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.blind_signature.verify.failed")

            public static let pedersenSetupSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.setup.succeeded")
            public static let pedersenSetupFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.setup.failed")
            public static let pedersenCommitSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.commit.succeeded")
            public static let pedersenCommitFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.commit.failed")
            public static let pedersenVerifySucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.verify.succeeded")
            public static let pedersenVerifyFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.verify.failed")
            public static let pedersenCombineSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.combine.succeeded")
            public static let pedersenCombineFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.combine.failed")
            public static let pedersenCommitmentParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.commitment.parse.succeeded")
            public static let pedersenCommitmentParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.commitment.parse.failed")
            public static let pedersenNonceParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.nonce.parse.succeeded")
            public static let pedersenNonceParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.pedersen.nonce.parse.failed")

            public static let sha256Succeeded = OpalDiagnostics.Event(rawValue: "opalcrypto.hashing.sha256.succeeded")
            public static let hash256Succeeded = OpalDiagnostics.Event(rawValue: "opalcrypto.hashing.hash256.succeeded")
            public static let hash160Succeeded = OpalDiagnostics.Event(rawValue: "opalcrypto.hashing.hash160.succeeded")
            public static let hmacSHA512Succeeded = OpalDiagnostics.Event(rawValue: "opalcrypto.hashing.hmac_sha512.succeeded")
            public static let hmacSHA256Succeeded = OpalDiagnostics.Event(rawValue: "opalcrypto.hashing.hmac_sha256.succeeded")

            public static let base58DecodeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.encoding.base58.decode.failed")
            public static let base58CheckDecodeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.encoding.base58check.decode.failed")
            public static let base32DecodeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.encoding.base32.decode.failed")
        }

        public enum ErrorCodes {
            public static let ambiguousLanguage = "ambiguous_language"
            public static let cryptographyFailure = "cryptography_failure"
            public static let derivedKeyLengthExceedsLimit = "derived_key_length_exceeds_limit"
            public static let depthOverflow = "depth_overflow"
            public static let emptyCommitmentList = "empty_commitment_list"
            public static let emptySalt = "empty_salt"
            public static let hardenedDerivationRequiresPrivateKey = "hardened_derivation_requires_private_key"
            public static let insecureAlternateBasePoint = "insecure_alternate_base_point"
            public static let invalidAlternateBasePoint = "invalid_alternate_base_point"
            public static let invalidAlternateBasePointLength = "invalid_alternate_base_point_length"
            public static let invalidAlternateBasePointPrefix = "invalid_alternate_base_point_prefix"
            public static let invalidBase58 = "invalid_base58"
            public static let invalidChainCodeLength = "invalid_chain_code_length"
            public static let invalidCharacterFound = "invalid_character_found"
            public static let invalidChecksum = "invalid_checksum"
            public static let invalidCiphertext = "invalid_ciphertext"
            public static let invalidCommitment = "invalid_commitment"
            public static let invalidCommitmentLength = "invalid_commitment_length"
            public static let invalidCompressionMarker = "invalid_compression_marker"
            public static let invalidDerivedKey = "invalid_derived_key"
            public static let invalidDerivedKeyLength = "invalid_derived_key_length"
            public static let invalidDepthMetadata = "invalid_depth_metadata"
            public static let invalidDigestLength = "invalid_digest_length"
            public static let invalidEntropyLength = "invalid_entropy_length"
            public static let invalidFiveBitValue = "invalid_five_bit_value"
            public static let invalidIterationCount = "invalid_iteration_count"
            public static let invalidNonce = "invalid_nonce"
            public static let invalidNonceLength = "invalid_nonce_length"
            public static let invalidNoncePoint = "invalid_nonce_point"
            public static let invalidNoncePointLength = "invalid_nonce_point_length"
            public static let invalidNoncePointPrefix = "invalid_nonce_point_prefix"
            public static let invalidPaddedPlaintextLength = "invalid_padded_plaintext_length"
            public static let invalidParentFingerprintLength = "invalid_parent_fingerprint_length"
            public static let invalidPayloadLength = "invalid_payload_length"
            public static let invalidPrivateKey = "invalid_private_key"
            public static let invalidPrivateKeyLength = "invalid_private_key_length"
            public static let invalidPublicKey = "invalid_public_key"
            public static let invalidPublicKeyLength = "invalid_public_key_length"
            public static let invalidPublicKeyPrefix = "invalid_public_key_prefix"
            public static let invalidRequestLength = "invalid_request_length"
            public static let invalidRequestScalar = "invalid_request_scalar"
            public static let invalidResponseLength = "invalid_response_length"
            public static let invalidResponseScalar = "invalid_response_scalar"
            public static let invalidSeedLength = "invalid_seed_length"
            public static let invalidSignature = "invalid_signature"
            public static let invalidSignatureLength = "invalid_signature_length"
            public static let invalidSymmetricKeyLength = "invalid_symmetric_key_length"
            public static let invalidTweak = "invalid_tweak"
            public static let invalidTweakLength = "invalid_tweak_length"
            public static let invalidVersion = "invalid_version"
            public static let invalidWord = "invalid_word"
            public static let invalidWordCount = "invalid_word_count"
            public static let invalidWordList = "invalid_word_list"
            public static let messageTooLong = "message_too_long"
            public static let mismatchedSetup = "mismatched_setup"
            public static let nonceAlreadyUsed = "nonce_already_used"
            public static let nonCanonicalDER = "non_canonical_der"
            public static let paddedPlaintextLengthMustBeMultipleOf16 = "padded_plaintext_length_must_be_multiple_of_16"
            public static let randomGenerationFailed = "random_generation_failed"
            public static let verificationFailed = "verification_failed"
            public static let wordListResourceMissing = "word_list_resource_missing"
        }

        public static var currentTraceID: TraceID? {
            OpalDiagnostics.currentTraceID
        }

        public static func withTraceID<Success>(
            _ traceID: TraceID,
            operation: () throws -> Success
        ) rethrows -> Success {
            try OpalDiagnostics.withTraceID(traceID, operation: operation)
        }

        public static func withTraceID<Success>(
            _ traceID: TraceID,
            operation: () async throws -> Success
        ) async rethrows -> Success {
            try await OpalDiagnostics.withTraceID(traceID, operation: operation)
        }
    }
}
