// OpalCrypto.Signature.ECDSA~Verification.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto.Signature.ECDSA {
    public func verify(
        message: Data,
        publicKey: OpalCrypto.Secp256k1.PublicKey
    ) throws -> Bool {
        try verify(
            message: message,
            verificationKey: OpalCrypto.Signature.VerificationKey(publicKey: publicKey)
        )
    }

    public func verify(
        message: Data,
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) throws -> Bool {
        let fields = verifyFields(
            payloadLengthField: OpalDiagnostics.Field.messageLengthField(message.count),
            verificationKey: verificationKey
        )
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
            event: OpalDiagnostics.Event.ecdsaVerifyBegin,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaVerifyBegin),
            fields: fields
        )
        do {
            let digestData32Bytes = SecureHashAlgorithm256Model.hash(message)
            let result = try StandardsForEfficientCryptography256k1CurveModel.verify(
                signature: signatureModel,
                digestData32Bytes: digestData32Bytes,
                verificationKeyModel: verificationKey.verificationKeyModel
            )
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: result
                    ? OpalDiagnostics.Event.ecdsaVerifySucceeded
                    : OpalDiagnostics.Event.ecdsaVerifyFailed,
                level: .opalCryptoDefault(for: result
                    ? OpalDiagnostics.Event.ecdsaVerifySucceeded
                    : OpalDiagnostics.Event.ecdsaVerifyFailed),
                fields: fields + [OpalDiagnostics.Field.resultField(result)]
            )
            return result
        } catch {
            if OpalCrypto.Signature.isInvalidVerificationSignatureError(error) {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.ecdsaVerifyFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaVerifyFailed),
                    fields: fields + [OpalDiagnostics.Field.resultField(false)]
                )
                return false
            }
            let mappedError = OpalCrypto.Signature.mapCryptographyError(error)
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.ecdsaVerifyFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaVerifyFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
            )
            throw mappedError
        }
    }

    public func verify(
        digest: OpalCrypto.Signature.Digest,
        publicKey: OpalCrypto.Secp256k1.PublicKey
    ) throws -> Bool {
        try verify(
            digest: digest,
            verificationKey: OpalCrypto.Signature.VerificationKey(publicKey: publicKey)
        )
    }

    public func verify(
        digest: OpalCrypto.Signature.Digest,
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) throws -> Bool {
        let fields = verifyFields(
            payloadLengthField: OpalDiagnostics.Field.publicField(
                "digest_byte_count",
                digest.rawRepresentation.count
            ),
            verificationKey: verificationKey
        )
        OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
            event: OpalDiagnostics.Event.ecdsaVerifyBegin,
            level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaVerifyBegin),
            fields: fields
        )
        do {
            let result = try StandardsForEfficientCryptography256k1CurveModel.verify(
                signature: signatureModel,
                digestData32Bytes: digest.rawRepresentation,
                verificationKeyModel: verificationKey.verificationKeyModel
            )
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: result
                    ? OpalDiagnostics.Event.ecdsaVerifySucceeded
                    : OpalDiagnostics.Event.ecdsaVerifyFailed,
                level: .opalCryptoDefault(for: result
                    ? OpalDiagnostics.Event.ecdsaVerifySucceeded
                    : OpalDiagnostics.Event.ecdsaVerifyFailed),
                fields: fields + [OpalDiagnostics.Field.resultField(result)]
            )
            return result
        } catch {
            if OpalCrypto.Signature.isInvalidVerificationSignatureError(error) {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                    event: OpalDiagnostics.Event.ecdsaVerifyFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaVerifyFailed),
                    fields: fields + [OpalDiagnostics.Field.resultField(false)]
                )
                return false
            }
            let mappedError = OpalCrypto.Signature.mapCryptographyError(error)
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.signature).record(
                event: OpalDiagnostics.Event.ecdsaVerifyFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.ecdsaVerifyFailed),
                fields: fields + OpalDiagnostics.Field.errorFields(mappedError)
            )
            throw mappedError
        }
    }

    private func verifyFields(
        payloadLengthField: OpalDiagnostics.Field,
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) -> [OpalDiagnostics.Field] {
        [
            OpalDiagnostics.Field.operationField("verify"),
            OpalDiagnostics.Field.algorithmField("ecdsa"),
            OpalDiagnostics.Field.formatField(format.diagnosticsName),
            payloadLengthField,
            OpalDiagnostics.Field.publicField(
                "verification_key_byte_count",
                verificationKey.verificationKeyModel.compressedPublicKeyData.count
            ),
            OpalDiagnostics.Field.signatureLengthField(rawRepresentation.count)
        ]
    }
}
