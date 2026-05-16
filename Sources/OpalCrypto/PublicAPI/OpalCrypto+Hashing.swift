// OpalCrypto+Hashing.swift

import Foundation

extension OpalCrypto {
    public enum Hashing {
        public static func sha256(_ data: Data) -> Data {
            let digest = SecureHashAlgorithm256Model.hash(data)
            recordHashSucceeded(
                OpalCryptoDiagnostics.Event.sha256Succeeded,
                algorithm: "sha256",
                inputByteCount: data.count,
                outputByteCount: digest.count
            )
            return digest
        }

        public static func hash256(_ data: Data) -> Data {
            let digest = SecureHash256Model.hash(data)
            recordHashSucceeded(
                OpalCryptoDiagnostics.Event.hash256Succeeded,
                algorithm: "hash256",
                inputByteCount: data.count,
                outputByteCount: digest.count
            )
            return digest
        }

        public static func hash160(_ data: Data) -> Data {
            let digest = SecureHash160Model.hash(data)
            recordHashSucceeded(
                OpalCryptoDiagnostics.Event.hash160Succeeded,
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
                OpalCryptoDiagnostics.Event.hmacSHA512Succeeded,
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
                OpalCryptoDiagnostics.Event.hmacSHA256Succeeded,
                algorithm: "hmac_sha256",
                inputByteCount: data.count,
                outputByteCount: digest.count,
                keyByteCount: key.count
            )
            return digest
        }

        private static func recordHashSucceeded(
            _ event: OpalCrypto.Diagnostics.Event,
            algorithm: String,
            inputByteCount: Int,
            outputByteCount: Int,
            keyByteCount: Int? = nil
        ) {
            var fields = [
                OpalCryptoDiagnostics.operationField("hash"),
                OpalCryptoDiagnostics.algorithmField(algorithm),
                OpalCryptoDiagnostics.inputLengthField(inputByteCount),
                OpalCryptoDiagnostics.outputLengthField(outputByteCount)
            ]
            if let keyByteCount {
                fields.append(OpalCryptoDiagnostics.publicField("key_byte_count", keyByteCount))
            }
            OpalCryptoDiagnostics.record(
                event,
                category: OpalCryptoDiagnostics.Category.hashing,
                fields: fields
            )
        }
    }
}
