// OpalCryptoDiagnostics.swift

import Foundation
import OpalDiagnostics

enum OpalCryptoDiagnostics {
    typealias Field = OpalDiagnostics.Field

    enum Category {
        static let crypto = OpalDiagnostics.Category.crypto
        static let signature = OpalDiagnostics.Category(rawValue: "crypto.signature")
        static let key = OpalDiagnostics.Category(rawValue: "crypto.key")
        static let encoding = OpalDiagnostics.Category(rawValue: "crypto.encoding")
        static let communication = OpalDiagnostics.Category(rawValue: "crypto.communication")
        static let blindSignature = OpalDiagnostics.Category(rawValue: "crypto.blind_signature")
        static let pedersen = OpalDiagnostics.Category(rawValue: "crypto.pedersen")
        static let hashing = OpalDiagnostics.Category(rawValue: "crypto.hashing")
    }

    enum Event {
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
        static let publicKeyParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.parse.succeeded")
        static let publicKeyParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.parse.failed")
        static let publicKeyDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.derive.succeeded")
        static let publicKeyDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.derive.failed")
        static let publicKeysDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.batch_derive.succeeded")
        static let publicKeysDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.public.batch_derive.failed")
        static let sharedSecretDeriveSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.shared_secret.derive.succeeded")
        static let sharedSecretDeriveFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.shared_secret.derive.failed")
        static let wifParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.parse.succeeded")
        static let wifParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.parse.failed")
        static let wifSerializeSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.serialize.succeeded")
        static let wifSerializeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.wif.serialize.failed")
        static let mnemonicParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.parse.succeeded")
        static let mnemonicParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.parse.failed")
        static let mnemonicGenerateSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.generate.succeeded")
        static let mnemonicGenerateFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.mnemonic.generate.failed")
        static let extendedPrivateParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.parse.succeeded")
        static let extendedPrivateParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.parse.failed")
        static let extendedPrivateRootSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.root.succeeded")
        static let extendedPrivateRootFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_private.root.failed")
        static let extendedPublicParseSucceeded = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_public.parse.succeeded")
        static let extendedPublicParseFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.key.extended_public.parse.failed")

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

        static let base58DecodeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.encoding.base58.decode.failed")
        static let base58CheckDecodeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.encoding.base58check.decode.failed")
        static let base32DecodeFailed = OpalDiagnostics.Event(rawValue: "opalcrypto.encoding.base32.decode.failed")
    }

    static func record(
        _ event: OpalDiagnostics.Event,
        category: OpalDiagnostics.Category,
        level: OpalDiagnostics.Level = .debug,
        traceID: OpalDiagnostics.TraceID? = nil,
        fields: [OpalDiagnostics.Field] = []
    ) {
        OpalDiagnostics.logger(category: category).record(
            event: event,
            level: level,
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
            publicField("error_type", String(reflecting: Swift.type(of: error))),
            privateField("error_message", String(describing: error))
        ]
    }
}
