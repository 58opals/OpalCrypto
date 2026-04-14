// OpalCrypto+Encoding.swift

import Foundation

extension OpalCrypto {
    public enum Encoding {

        public static func encodeBase58(_ data: Data) -> String {
            Base58EncodingModel.encode(data)
        }

        public static func decodeBase58(_ text: String) -> Data? {
            Base58EncodingModel.decode(text)
        }

        public static func encodeBase32(_ data: Data, interpretedAsFiveBitValues: Bool) throws -> String {
            do {
                return try Base32EncodingModel.encode(
                    data,
                    interpretedAsFiveBitValues: interpretedAsFiveBitValues
                )
            } catch let error as Base32EncodingModel.Error {
                throw mapBase32Error(error)
            }
        }

        public static func decodeBase32(_ text: String, interpretedAsFiveBitValues: Bool) throws -> Data {
            do {
                return try Base32EncodingModel.decode(
                    text,
                    interpretedAsFiveBitValues: interpretedAsFiveBitValues
                )
            } catch let error as Base32EncodingModel.Error {
                throw mapBase32Error(error)
            }
        }

        public static func computePolymodChecksum(_ values: [UInt8]) -> UInt64 {
            PolynomialModuloChecksumModel.compute(values)
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
