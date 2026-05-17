// OpalCrypto+Hashing.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto {
    public enum Hashing {
        public static func sha256(_ data: Data) -> Data {
            let digest = SecureHashAlgorithm256Model.hash(data)
            recordHashSucceeded(
                OpalDiagnostics.Event.sha256Succeeded,
                algorithm: "sha256",
                inputByteCount: data.count,
                outputByteCount: digest.count
            )
            return digest
        }

        public static func hash256(_ data: Data) -> Data {
            let digest = SecureHash256Model.hash(data)
            recordHashSucceeded(
                OpalDiagnostics.Event.hash256Succeeded,
                algorithm: "hash256",
                inputByteCount: data.count,
                outputByteCount: digest.count
            )
            return digest
        }

        public static func hash160(_ data: Data) -> Data {
            let digest = SecureHash160Model.hash(data)
            recordHashSucceeded(
                OpalDiagnostics.Event.hash160Succeeded,
                algorithm: "hash160",
                inputByteCount: data.count,
                outputByteCount: digest.count
            )
            return digest
        }

        public static func hmacSHA512(data: Data, key: Data) -> Data {
            let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model
                .hash(data, key: key)
            recordHashSucceeded(
                OpalDiagnostics.Event.hmacSHA512Succeeded,
                algorithm: "hmac_sha512",
                inputByteCount: data.count,
                outputByteCount: digest.count,
                keyByteCount: key.count
            )
            return digest
        }

        public static func hmacSHA256(data: Data, key: Data) -> Data {
            let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model
                .hash(data, key: key)
            recordHashSucceeded(
                OpalDiagnostics.Event.hmacSHA256Succeeded,
                algorithm: "hmac_sha256",
                inputByteCount: data.count,
                outputByteCount: digest.count,
                keyByteCount: key.count
            )
            return digest
        }

        private static func recordHashSucceeded(
            _ event: OpalDiagnostics.Event,
            algorithm: String,
            inputByteCount: Int,
            outputByteCount: Int,
            keyByteCount: Int? = nil
        ) {
            var fields = [
                OpalDiagnostics.Field.operationField("hash"),
                OpalDiagnostics.Field.algorithmField(algorithm),
                OpalDiagnostics.Field.inputLengthField(inputByteCount),
                OpalDiagnostics.Field.outputLengthField(outputByteCount)
            ]
            if let keyByteCount {
                fields.append(OpalDiagnostics.Field.publicField("key_byte_count", keyByteCount))
            }
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.hashing).record(
                event: event,
                level: .opalCryptoDefault(for: event),
                fields: fields
            )
        }
    }
}
