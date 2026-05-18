// Base32EncodingCodec+Error.swift

extension Base32EncodingCodec {
    internal enum Error: Swift.Error {
        case invalidFiveBitValue(actual: UInt8)
        case invalidCharacterFound
    }
}
