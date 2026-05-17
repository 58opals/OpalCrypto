// Base58CheckCodec+Error.swift

extension Base58CheckCodec {
    internal enum Error: Swift.Error, Equatable {
        case invalidBase58
        case invalidPayloadLength(actual: Int)
        case invalidChecksum
    }
}
