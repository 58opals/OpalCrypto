// Base32EncodingModel+Error.swift

extension Base32EncodingModel {
    internal enum Error: Swift.Error {
        case invalidFiveBitValue(actual: UInt8)
        case invalidCharacterFound
    }
}
