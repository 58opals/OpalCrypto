// OpalCrypto+Encoding.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto {
    public enum Encoding {

        public static func encodeBase58(_ data: Data) -> String {
            Base58EncodingCodec.encode(data)
        }

        public static func decodeBase58(_ text: String) -> Data? {
            let decoded = Base58EncodingCodec.decode(text)
            if decoded == nil {
                OpalDiagnostics.logger(category: OpalDiagnostics.Category.encoding).record(
                    event: OpalDiagnostics.Event.base58DecodeFailed,
                    level: .opalCryptoDefault(for: OpalDiagnostics.Event.base58DecodeFailed),
                    fields: [
                        OpalDiagnostics.Field.operationField("base58_decode"),
                        OpalDiagnostics.Field.publicField("input_character_count", text.count),
                        OpalDiagnostics.Field.errorCode(
                            OpalDiagnostics.ErrorCode(rawValue: "invalid_base58")
                        )
                    ]
                )
            }
            return decoded
        }

        public static func encodeBase32Bytes(_ data: Data) throws -> String {
            do {
                return try Base32EncodingCodec.encode(
                    data,
                    interpretedAsFiveBitValues: false
                )
            } catch let error as Base32EncodingCodec.Error {
                throw mapBase32Error(error)
            }
        }

        public static func decodeBase32Bytes(_ text: String) throws -> Data {
            do {
                return try Base32EncodingCodec.decode(
                    text,
                    interpretedAsFiveBitValues: false
                )
            } catch let error as Base32EncodingCodec.Error {
                let mappedError = mapBase32Error(error)
                recordBase32DecodeFailure(mappedError, text: text, mode: "bytes")
                throw mappedError
            }
        }

        public static func encodeBase32Values(_ values: FiveBitValues) throws -> String {
            do {
                return try Base32EncodingCodec.encode(
                    values.rawRepresentation,
                    interpretedAsFiveBitValues: true
                )
            } catch let error as Base32EncodingCodec.Error {
                throw mapBase32Error(error)
            }
        }

        public static func decodeBase32Values(_ text: String) throws -> FiveBitValues {
            do {
                let values = try Base32EncodingCodec.decode(
                    text,
                    interpretedAsFiveBitValues: true
                )
                return try FiveBitValues(rawRepresentation: values)
            } catch let error as Base32EncodingCodec.Error {
                let mappedError = mapBase32Error(error)
                recordBase32DecodeFailure(mappedError, text: text, mode: "five_bit_values")
                throw mappedError
            }
        }

        public static func computePolymodChecksum(_ values: FiveBitValues) -> UInt64 {
            PolynomialModuloChecksumModel.compute(Array(values.rawRepresentation))
        }

        private static func mapBase32Error(_ error: Base32EncodingCodec.Error) -> Error {
            switch error {
            case .invalidFiveBitValue(let actual):
                return .invalidFiveBitValue(actual: actual)
            case .invalidCharacterFound:
                return .invalidCharacterFound
            }
        }

        private static func recordBase32DecodeFailure(
            _ error: Error,
            text: String,
            mode: String
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.encoding).record(
                event: OpalDiagnostics.Event.base32DecodeFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.base32DecodeFailed),
                fields: [
                    OpalDiagnostics.Field.operationField("base32_decode"),
                    OpalDiagnostics.Field.publicField("mode", mode),
                    OpalDiagnostics.Field.publicField("input_character_count", text.count)
                ] + OpalDiagnostics.Field.errorFields(error)
            )
        }
    }
}
