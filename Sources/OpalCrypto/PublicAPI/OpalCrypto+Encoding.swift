import Foundation

extension OpalCrypto {
    public enum Encoding {
        public static func encodeBase58(_ data: Data) -> String {
            Base58EncodingModel.encode(data)
        }

        public static func decodeBase58(_ text: String) -> Data? {
            Base58EncodingModel.decode(text)
        }

        public static func encodeBase32(_ data: Data, interpretedAsFiveBitValues: Bool) -> String {
            Base32EncodingModel.encode(data, interpretedAsFiveBitValues: interpretedAsFiveBitValues)
        }

        public static func decodeBase32(_ text: String, interpretedAsFiveBitValues: Bool) throws -> Data {
            try Base32EncodingModel.decode(text, interpretedAsFiveBitValues: interpretedAsFiveBitValues)
        }

        public static func computePolymodChecksum(_ values: [UInt8]) -> UInt64 {
            PolynomialModuloChecksumModel.compute(values)
        }
    }
}
