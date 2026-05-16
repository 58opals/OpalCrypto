// OpalCrypto+Encoding.swift

import Foundation

extension OpalCrypto {
    public enum Encoding {

        public static func encodeBase58(_ data: Data) -> String {
            Base58EncodingModel.encode(data)
        }

        public static func decodeBase58(_ text: String) -> Data? {
            let decoded = Base58EncodingModel.decode(text)
            if decoded == nil {
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.base58DecodeFailed,
                    category: OpalCryptoDiagnostics.Category.encoding,
                    fields: [
                        OpalCryptoDiagnostics.operationField("base58_decode"),
                        OpalCryptoDiagnostics.publicField("input_character_count", text.count)
                    ]
                )
            }
            return decoded
        }

        public static func encodeBase32Bytes(_ data: Data) throws -> String {
            do {
                return try Base32EncodingModel.encode(
                    data,
                    interpretedAsFiveBitValues: false
                )
            } catch let error as Base32EncodingModel.Error {
                throw mapBase32Error(error)
            }
        }

        public static func decodeBase32Bytes(_ text: String) throws -> Data {
            do {
                return try Base32EncodingModel.decode(
                    text,
                    interpretedAsFiveBitValues: false
                )
            } catch let error as Base32EncodingModel.Error {
                let mappedError = mapBase32Error(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.base32DecodeFailed,
                    category: OpalCryptoDiagnostics.Category.encoding,
                    fields: [
                        OpalCryptoDiagnostics.operationField("base32_decode"),
                        OpalCryptoDiagnostics.publicField("mode", "bytes"),
                        OpalCryptoDiagnostics.publicField("input_character_count", text.count)
                    ] + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public static func encodeBase32Values(_ values: FiveBitValues) throws -> String {
            do {
                return try Base32EncodingModel.encode(
                    values.rawRepresentation,
                    interpretedAsFiveBitValues: true
                )
            } catch let error as Base32EncodingModel.Error {
                throw mapBase32Error(error)
            }
        }

        public static func decodeBase32Values(_ text: String) throws -> FiveBitValues {
            do {
                let values = try Base32EncodingModel.decode(
                    text,
                    interpretedAsFiveBitValues: true
                )
                return try FiveBitValues(rawRepresentation: values)
            } catch let error as Base32EncodingModel.Error {
                let mappedError = mapBase32Error(error)
                OpalCryptoDiagnostics.record(
                    OpalCryptoDiagnostics.Event.base32DecodeFailed,
                    category: OpalCryptoDiagnostics.Category.encoding,
                    fields: [
                        OpalCryptoDiagnostics.operationField("base32_decode"),
                        OpalCryptoDiagnostics.publicField("mode", "five_bit_values"),
                        OpalCryptoDiagnostics.publicField("input_character_count", text.count)
                    ] + OpalCryptoDiagnostics.errorFields(mappedError)
                )
                throw mappedError
            }
        }

        public static func computePolymodChecksum(_ values: FiveBitValues) -> UInt64 {
            PolynomialModuloChecksumModel.compute(Array(values.rawRepresentation))
        }

        private static func mapBase32Error(_ error: Base32EncodingModel.Error) -> Error {
            switch error {
            case .invalidFiveBitValue(let actual):
                return .invalidFiveBitValue(actual: actual)
            case .invalidCharacterFound:
                return .invalidCharacterFound
            }
        }
    }
}
