// OpalCrypto.Signature.ECDSA~Signing.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Signature.ECDSA {
    /// Hashes `message` once with SHA-256, then signs that digest with ECDSA.
    ///
    /// Prefer ``signSHA256(message:privateKey:format:noncePolicy:)`` in new code
    /// when the hashing contract should be explicit at the call site. To sign an
    /// already computed digest without hashing it again, use
    /// ``sign(digest:privateKey:format:noncePolicy:)``.
    public static func sign(
        message: Data,
        privateKey: OpalCrypto.Secp256k1.PrivateKey,
        format: OpalCrypto.Signature.ECDSAFormat = .der,
        noncePolicy: OpalCrypto.Signature.ECDSANoncePolicy = .rfc6979
    ) throws -> OpalCrypto.Signature.ECDSA {
        try signSHA256(
            message: message,
            privateKey: privateKey,
            format: format,
            noncePolicy: noncePolicy
        )
    }

    /// Hashes `message` once with SHA-256, then signs that digest with ECDSA.
    ///
    /// - Parameters:
    ///   - message: Arbitrary message bytes that this operation hashes once.
    ///   - privateKey: The secp256k1 private key used to create the signature.
    ///   - format: The serialized signature format.
    ///   - noncePolicy: The nonce-generation policy. RFC 6979 is the default.
    /// - Returns: An ECDSA signature over `SHA256(message)`.
    public static func signSHA256(
        message: Data,
        privateKey: OpalCrypto.Secp256k1.PrivateKey,
        format: OpalCrypto.Signature.ECDSAFormat = .der,
        noncePolicy: OpalCrypto.Signature.ECDSANoncePolicy = .rfc6979
    ) throws -> OpalCrypto.Signature.ECDSA {
        try sign(
            digestData32Bytes: SecureHashAlgorithm256Model.hash(message),
            privateKeyScalar: privateKey.scalarModel,
            format: format,
            noncePolicy: noncePolicy,
            privateKeyByteCount: privateKey.rawRepresentation.count,
            payloadLengthField: OpalDiagnostics.Field.messageLengthField(message.count)
        )
    }

    /// Signs an already computed 32-byte digest without hashing it again.
    public static func sign(
        digest: OpalCrypto.Signature.Digest,
        privateKey: OpalCrypto.Secp256k1.PrivateKey,
        format: OpalCrypto.Signature.ECDSAFormat = .der,
        noncePolicy: OpalCrypto.Signature.ECDSANoncePolicy = .rfc6979
    ) throws -> OpalCrypto.Signature.ECDSA {
        try sign(
            digestData32Bytes: digest.rawRepresentation,
            privateKeyScalar: privateKey.scalarModel,
            format: format,
            noncePolicy: noncePolicy,
            privateKeyByteCount: privateKey.rawRepresentation.count,
            payloadLengthField: OpalDiagnostics.Field.publicField(
                "digest_byte_count",
                digest.rawRepresentation.count
            )
        )
    }

    internal static func sign(
        digestData32Bytes: Data,
        privateKeyScalar: ScalarModel,
        format: OpalCrypto.Signature.ECDSAFormat,
        noncePolicy: OpalCrypto.Signature.ECDSANoncePolicy,
        privateKeyByteCount: Int,
        payloadLengthField: OpalDiagnostics.Field
    ) throws -> OpalCrypto.Signature.ECDSA {
        let fields = signFields(
            format: format,
            noncePolicy: noncePolicy,
            privateKeyByteCount: privateKeyByteCount,
            payloadLengthField: payloadLengthField
        )
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
            event: OpalDiagnostics.Event.ecdsaSignBegin,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaSignBegin),
            fields: fields
        )
        do {
            let signatureModel = try StandardsForEfficientCryptography256k1CurveModel
                .sign(
                    digestData32Bytes: digestData32Bytes,
                    privateKeyScalar: privateKeyScalar,
                    nonce: noncePolicy.internalECDSANoncePolicy
                )
            let signature = try OpalCrypto.Signature.ECDSA(signatureModel: signatureModel, format: format)
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.ecdsaSignSucceeded,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaSignSucceeded),
                fields: fields + [
                    OpalDiagnostics.Field.signatureLengthField(signature.rawRepresentation.count)
                ]
            )
            return signature
        } catch {
            let mappedError = OpalCrypto.Signature.mapDiagnosticsError(error)
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.ecdsaSignFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaSignFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
            )
            throw mappedError
        }
    }

    private static func signFields(
        format: OpalCrypto.Signature.ECDSAFormat,
        noncePolicy: OpalCrypto.Signature.ECDSANoncePolicy,
        privateKeyByteCount: Int,
        payloadLengthField: OpalDiagnostics.Field
    ) -> [OpalDiagnostics.Field] {
        [
            OpalDiagnostics.Field.operationField("sign"),
            OpalDiagnostics.Field.algorithmField("ecdsa"),
            OpalDiagnostics.Field.formatField(format.diagnosticsName),
            OpalDiagnostics.Field.publicField("nonce_policy", noncePolicy.diagnosticsName),
            OpalDiagnostics.Field.publicField("private_key_byte_count", privateKeyByteCount),
            payloadLengthField
        ]
    }
}
