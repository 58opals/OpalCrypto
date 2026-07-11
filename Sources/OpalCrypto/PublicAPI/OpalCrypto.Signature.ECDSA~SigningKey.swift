// OpalCrypto.Signature.ECDSA~SigningKey.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Signature.ECDSA {
    internal static func sign(
        message: Data,
        parsedPrivateKeyModel: ParsedPrivateKeyModel,
        format: OpalCrypto.Signature.ECDSAFormat = .der,
        noncePolicy: OpalCrypto.Signature.ECDSANoncePolicy = .rfc6979
    ) throws -> OpalCrypto.Signature.ECDSA {
        let fields = signFields(
            format: format,
            noncePolicy: noncePolicy,
            privateKeyByteCount: OpalCrypto.Secp256k1.SigningKey.privateKeyByteCount,
            payloadLengthField: OpalDiagnostics.Field.messageLengthField(message.count)
        )
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
            event: OpalDiagnostics.Event.ecdsaSignBegin,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaSignBegin),
            fields: fields
        )
        do {
            let signatureData = try EllipticCurveDigitalSignatureAlgorithmModel.sign(
                message: message,
                with: parsedPrivateKeyModel,
                in: format.internalFormat,
                nonceFunction: noncePolicy.internalNoncePolicy
            )
            let signature = try OpalCrypto.Signature.ECDSA(rawRepresentation: signatureData, format: format)
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

    internal static func sign(
        digest: OpalCrypto.Signature.Digest,
        parsedPrivateKeyModel: ParsedPrivateKeyModel,
        format: OpalCrypto.Signature.ECDSAFormat = .der,
        noncePolicy: OpalCrypto.Signature.ECDSANoncePolicy = .rfc6979
    ) throws -> OpalCrypto.Signature.ECDSA {
        let fields = signFields(
            format: format,
            noncePolicy: noncePolicy,
            privateKeyByteCount: OpalCrypto.Secp256k1.SigningKey.privateKeyByteCount,
            payloadLengthField: OpalDiagnostics.Field.publicField(
                "digest_byte_count",
                digest.rawRepresentation.count
            )
        )
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
            event: OpalDiagnostics.Event.ecdsaSignBegin,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaSignBegin),
            fields: fields
        )
        do {
            let signatureModel = try StandardsForEfficientCryptography256k1CurveModel.sign(
                digestData32Bytes: digest.rawRepresentation,
                privateKeyScalar: parsedPrivateKeyModel.scalar,
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

    static func signFields(
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
