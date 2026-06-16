// OpalCrypto.Communication~Decryption.swift

import Foundation
import OpalDiagnostics


extension OpalCrypto.Communication {
    public static func decrypt(
        _ ciphertext: Ciphertext,
        privateKey: OpalCrypto.Secp256k1.PrivateKey
    ) throws -> DecryptionResult {
        let fields = decryptFields(
            mode: "private_key",
            ciphertextByteCount: ciphertext.rawRepresentation.count,
            keyLengthField: OpalDiagnostics.Field.publicField(
                "private_key_byte_count",
                privateKey.rawRepresentation.count
            )
        )
        recordCommunication(
            event: OpalDiagnostics.Event.communicationDecryptBegin,
            fields: fields
        )
        do {
            let result = DecryptionResult(
                resultModel: try CommunicationBoxModel.decrypt(
                    ciphertext.rawRepresentation,
                    privateKey: privateKey.rawRepresentation
                )
            )
            recordCommunication(
                event: OpalDiagnostics.Event.communicationDecryptSucceeded,
                fields: fields + [
                    OpalDiagnostics.Field.publicField("plaintext_byte_count", result.message.count),
                    OpalDiagnostics.Field.publicField("symmetric_key_byte_count", result.symmetricKey.rawRepresentation.count)
                ]
            )
            return result
        } catch let error as CommunicationBoxModel.Error {
            let mappedError = mapError(error)
            recordCommunicationFailed(
                event: OpalDiagnostics.Event.communicationDecryptFailed,
                error: mappedError,
                fields: fields
            )
            throw mappedError
        }
    }

    public static func decrypt(
        _ ciphertext: Ciphertext,
        symmetricKey: SymmetricKey
    ) throws -> Data {
        let fields = decryptFields(
            mode: "symmetric_key",
            ciphertextByteCount: ciphertext.rawRepresentation.count,
            keyLengthField: OpalDiagnostics.Field.publicField(
                "symmetric_key_byte_count",
                symmetricKey.rawRepresentation.count
            )
        )
        recordCommunication(
            event: OpalDiagnostics.Event.communicationDecryptBegin,
            fields: fields
        )
        do {
            let message = try CommunicationBoxModel.decrypt(
                ciphertext.rawRepresentation,
                symmetricKey: symmetricKey.rawRepresentation
            )
            recordCommunication(
                event: OpalDiagnostics.Event.communicationDecryptSucceeded,
                fields: fields + [
                    OpalDiagnostics.Field.publicField("plaintext_byte_count", message.count)
                ]
            )
            return message
        } catch let error as CommunicationBoxModel.Error {
            let mappedError = mapError(error)
            recordCommunicationFailed(
                event: OpalDiagnostics.Event.communicationDecryptFailed,
                error: mappedError,
                fields: fields
            )
            throw mappedError
        }
    }

    private static func decryptFields(
        mode: String,
        ciphertextByteCount: Int,
        keyLengthField: OpalDiagnostics.Field
    ) -> [OpalDiagnostics.Field] {
        [
            OpalDiagnostics.Field.operationField("decrypt"),
            OpalDiagnostics.Field.publicField("mode", mode),
            OpalDiagnostics.Field.ciphertextLengthField(ciphertextByteCount),
            OpalDiagnostics.Field.publicField(
                "minimum_ciphertext_byte_count",
                CommunicationBoxModel.minimumCiphertextLength
            ),
            keyLengthField
        ]
    }
}
