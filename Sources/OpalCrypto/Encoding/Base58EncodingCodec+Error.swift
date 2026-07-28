// Base58EncodingCodec+Error.swift

extension Base58EncodingCodec {
    internal enum Error: Swift.Error, Equatable {
        case invalidCharacterFound
        case invalidMaximumDecodedByteCount(actual: Int)
        case decodedDataExceedsMaximumByteCount(maximum: Int)
    }
}
