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
        /// Prefer ``decodeBase58IfValid(_:maximumDecodedByteCount:)`` when optional failure is
        /// intended, or ``decodeBase58Validating(_:maximumDecodedByteCount:)`` when invalid
        /// input must be reported.
        /// - Parameter maximumDecodedByteCount: The largest decoded result the caller accepts.
        public static func decodeBase58(
            _ text: String,
            maximumDecodedByteCount: Int
        ) -> Data? {
            decodeBase58IfValid(text, maximumDecodedByteCount: maximumDecodedByteCount)
        }

        /// Decodes valid Base58 text, returning `nil` for invalid input.
        /// - Parameter maximumDecodedByteCount: The largest decoded result the caller accepts.
        public static func decodeBase58IfValid(
            _ text: String,
            maximumDecodedByteCount: Int
        ) -> Data? {
            try? decodeBase58Validating(
                text,
                maximumDecodedByteCount: maximumDecodedByteCount
            )
        }

        /// Decodes Base58 text and reports invalid input as an error.
        ///
        /// - Throws: ``OpalCrypto/Encoding/Base58DecodingError/invalidText`` when `text`
        ///   contains a character outside the Base58 alphabet, or another
        ///   ``OpalCrypto/Encoding/Base58DecodingError`` when the byte limit is invalid or
        ///   decoding would exceed it.
        /// - Parameter maximumDecodedByteCount: The largest decoded result the caller accepts.
        public static func decodeBase58Validating(
            _ text: String,
            maximumDecodedByteCount: Int
        ) throws -> Data {
            do {
                return try Base58EncodingCodec.decode(
                    text,
                    maximumDecodedByteCount: maximumDecodedByteCount
                )
            } catch let error as Base58EncodingCodec.Error {
                let mappedError = mapBase58Error(error)
                recordBase58DecodeFailure(mappedError, text: text)
                throw mappedError
            }
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
        /// - Parameter maximumDecodedByteCount: The largest decoded result the caller accepts.
        /// - Throws: ``OpalCrypto/Encoding/Error`` when the text is invalid, the byte limit is
        ///   negative, or decoding would exceed the limit.
        public static func decodeBase32Bytes(
            _ text: String,
            maximumDecodedByteCount: Int
        ) throws -> Data {
            try decodeBase32(
                text,
                interpretedAsFiveBitValues: false,
                maximumDecodedByteCount: maximumDecodedByteCount,
                mode: "bytes"
            )
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
                maximumDecodedByteCount: nil,
                mode: "five_bit_values"
            )
            return try FiveBitValues(rawRepresentation: values)
        }

        /// Computes the Bech32-style polymod value for validated five-bit symbols.
        public static func computePolymodChecksum(_ values: FiveBitValues) -> UInt64 {
            PolynomialModuloChecksumModel.compute(Array(values.rawRepresentation))
        }

        private static func mapBase58Error(
            _ error: Base58EncodingCodec.Error
        ) -> Base58DecodingError {
            switch error {
            case .invalidCharacterFound:
                return .invalidText
            case .invalidMaximumDecodedByteCount(let actual):
                return .invalidMaximumDecodedByteCount(actual: actual)
            case .decodedDataExceedsMaximumByteCount(let maximum):
                return .decodedDataExceedsMaximumByteCount(maximum: maximum)
            }
        }

        private static func recordBase58DecodeFailure(
            _ error: Base58DecodingError,
            text: String
        ) {
            OpalDiagnostics.logger(category: OpalDiagnostics.Category.encoding).record(
                event: OpalDiagnostics.Event.base58DecodeFailed,
                level: .opalCryptoDefault(for: OpalDiagnostics.Event.base58DecodeFailed),
                fields: [
                    OpalDiagnostics.Field.operationField("base58_decode"),
                    OpalDiagnostics.Field.formatField("base58"),
                    OpalDiagnostics.Field.publicField("input_character_count", text.count)
                ] + OpalDiagnostics.Field.errorFields(error)
            )
        }

        private static func mapBase32Error(_ error: Base32EncodingCodec.Error) -> Error {
            switch error {
            case .invalidFiveBitValue(let actual):
                return .invalidFiveBitValue(actual: actual)
            case .invalidCharacterFound:
                return .invalidCharacterFound
            case .invalidMaximumDecodedByteCount(let actual):
                return .invalidMaximumDecodedByteCount(actual: actual)
            case .decodedDataExceedsMaximumByteCount(let maximum):
                return .decodedDataExceedsMaximumByteCount(maximum: maximum)
            }
        }

        private static func decodeBase32(
            _ text: String,
            interpretedAsFiveBitValues: Bool,
            maximumDecodedByteCount: Int?,
            mode: String
        ) throws -> Data {
            do {
                return try Base32EncodingCodec.decode(
                    text,
                    interpretedAsFiveBitValues: interpretedAsFiveBitValues,
                    maximumDecodedByteCount: maximumDecodedByteCount
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
