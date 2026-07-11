// OpalCrypto+Hashing.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto {
    public enum Hashing {
        /// Returns the 32-byte SHA-256 digest of `data`.
        public static func sha256(_ data: Data) -> Data {
            let digest = SecureHashAlgorithm256Model.hash(data)
            recordHashingSucceeded(
                OpalDiagnostics.Event.sha256Succeeded,
                algorithm: "sha256",
                inputByteCount: data.count,
                outputByteCount: digest.count
            )
            return digest
        }

        /// Returns SHA-256(SHA-256(`data`)) as 32 bytes.
        public static func hash256(_ data: Data) -> Data {
            let digest = SecureHash256Model.hash(data)
            recordHashingSucceeded(
                OpalDiagnostics.Event.hash256Succeeded,
                algorithm: "hash256",
                inputByteCount: data.count,
                outputByteCount: digest.count
            )
            return digest
        }

        /// Returns RIPEMD-160(SHA-256(`data`)) as 20 bytes.
        public static func hash160(_ data: Data) -> Data {
            let digest = SecureHash160Model.hash(data)
            recordHashingSucceeded(
                OpalDiagnostics.Event.hash160Succeeded,
                algorithm: "hash160",
                inputByteCount: data.count,
                outputByteCount: digest.count
            )
            return digest
        }

        /// Returns the 64-byte HMAC-SHA-512 authentication code for `data`.
        public static func hmacSHA512(data: Data, key: Data) -> Data {
            let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model
                .hash(data, key: key)
            recordHashingSucceeded(
                OpalDiagnostics.Event.hmacSHA512Succeeded,
                operation: "hmac",
                algorithm: "hmac_sha512",
                inputByteCount: data.count,
                outputByteCount: digest.count,
                keyByteCount: key.count
            )
            return digest
        }

        /// Returns the 32-byte HMAC-SHA-256 authentication code for `data`.
        public static func hmacSHA256(data: Data, key: Data) -> Data {
            let digest = HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model
                .hash(data, key: key)
            recordHashingSucceeded(
                OpalDiagnostics.Event.hmacSHA256Succeeded,
                operation: "hmac",
                algorithm: "hmac_sha256",
                inputByteCount: data.count,
                outputByteCount: digest.count,
                keyByteCount: key.count
            )
            return digest
        }

        private static func recordHashingSucceeded(
            _ event: OpalDiagnostics.Event,
            operation: String = "hash",
            algorithm: String,
            inputByteCount: Int,
            outputByteCount: Int,
            keyByteCount: Int? = nil
        ) {
            var fields = [
                OpalDiagnostics.Field.operationField(operation),
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
