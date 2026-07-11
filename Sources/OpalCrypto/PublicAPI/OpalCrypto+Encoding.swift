// OpalCrypto+Encoding.swift

import Foundation
import OpalDiagnostics

extension OpalCrypto {
    public enum Encoding {

        /// Encodes arbitrary bytes using the Base58 alphabet.
        public static func encodeBase58(_ data: Data) -> String {
            Base58EncodingCodec.encode(data)
        }

        /// Decodes valid Base58 text, returning `nil` for invalid input.
        ///
        /// Prefer ``decodeBase58IfValid(_:)`` when optional failure is intended,
        /// or ``decodeBase58Validating(_:)`` when invalid input must be reported.
        public static func decodeBase58(_ text: String) -> Data? {
            decodeBase58IfValid(text)
        }

        /// Decodes valid Base58 text, returning `nil` for invalid input.
        public static func decodeBase58IfValid(_ text: String) -> Data? {
            try? decodeBase58Validating(text)
        }

        /// Decodes Base58 text and reports invalid input as an error.
        ///
        /// - Throws: ``OpalCrypto/Encoding/Base58DecodingError/invalidText`` when `text`
        ///   contains a character outside the Base58 alphabet.
        public static func decodeBase58Validating(_ text: String) throws -> Data {
            guard let decoded = Base58EncodingCodec.decode(text) else {
                recordBase58DecodeFailure(text: text)
                throw Base58DecodingError.invalidText
            }
            return decoded
        }

        /// Encodes arbitrary bytes using byte-mode Base32 conversion.
        public static func encodeBase32(bytes: Data) -> String {
            Base32EncodingCodec.encodeBytes(bytes)
        }

        /// Encodes validated five-bit symbols using the Base32 alphabet.
        public static func encodeBase32(values: FiveBitValues) -> String {
            Base32EncodingCodec.encodeFiveBitValues(values)
        }

        /// Encodes arbitrary bytes using byte-mode Base32 conversion.
        ///
        /// Prefer the nonthrowing ``encodeBase32(bytes:)`` entry point in new
        /// code. This source-compatible operation does not throw.
        public static func encodeBase32Bytes(_ data: Data) throws -> String {
            encodeBase32(bytes: data)
        }

        /// Decodes byte-mode Base32 text.
        public static func decodeBase32Bytes(_ text: String) throws -> Data {
            try decodeBase32(text, interpretedAsFiveBitValues: false, mode: "bytes")
        }

        /// Encodes validated five-bit symbols using the Base32 alphabet.
        ///
        /// Prefer the nonthrowing ``encodeBase32(values:)`` entry point in new
        /// code. This source-compatible operation does not throw.
        public static func encodeBase32Values(_ values: FiveBitValues) throws -> String {
            encodeBase32(values: values)
        }

        /// Decodes Base32 text as validated five-bit symbols.
        public static func decodeBase32Values(_ text: String) throws -> FiveBitValues {
            let values = try decodeBase32(
                text,
                interpretedAsFiveBitValues: true,
                mode: "five_bit_values"
            )
            return try FiveBitValues(rawRepresentation: values)
        }

        /// Computes the Bech32-style polymod value for validated five-bit symbols.
        public static func computePolymodChecksum(_ values: FiveBitValues) -> UInt64 {
            PolynomialModuloChecksumModel.compute(Array(values.rawRepresentation))
        }

        private static func recordBase58DecodeFailure(text: String) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.encoding).record(
                event: OpalDiagnostics.Event.base58DecodeFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.base58DecodeFailed),
                fields: [
                    OpalDiagnostics.Field.operationField("base58_decode"),
                    OpalDiagnostics.Field.formatField("base58"),
                    OpalDiagnostics.Field.publicField("input_character_count", text.count),
                    OpalDiagnostics.Field.errorCode(
                        OpalDiagnostics.ErrorCode(rawValue: "invalid_base58")
                    )
                ]
            )
        }

        private static func mapBase32Error(_ error: Base32EncodingCodec.Error) -> Error {
            switch error {
            case .invalidFiveBitValue(let actual):
                return .invalidFiveBitValue(actual: actual)
            case .invalidCharacterFound:
                return .invalidCharacterFound
            }
        }

        private static func decodeBase32(
            _ text: String,
            interpretedAsFiveBitValues: Bool,
            mode: String
        ) throws -> Data {
            do {
                return try Base32EncodingCodec.decode(
                    text,
                    interpretedAsFiveBitValues: interpretedAsFiveBitValues
                )
            } catch let error as Base32EncodingCodec.Error {
                let mappedError = mapBase32Error(error)
                recordBase32DecodeFailure(mappedError, text: text, mode: mode)
                throw mappedError
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
                    OpalDiagnostics.Field.formatField("base32"),
                    OpalDiagnostics.Field.publicField("mode", mode),
                    OpalDiagnostics.Field.publicField("input_character_count", text.count)
                ] + OpalDiagnostics.Field.errorFields(error)
            )
        }
    }
}
