// WalletImportFormatCodec+Error.swift

extension WalletImportFormatCodec {
    internal enum Error: Swift.Error, Equatable {
        case invalidBase58
        case invalidChecksum
        case invalidPayloadLength(actual: Int)
        case invalidVersion(actual: UInt8)
        case invalidCompressionMarker(actual: UInt8)
        case invalidPrivateKeyLength(actual: Int)
        case invalidPrivateKey
    }
}
