// OpalCrypto.Key.Mnemonic.Length~Metrics.swift

internal extension OpalCrypto.Key.Mnemonic.Length {
    var entropyByteCount: Int {
        (rawValue / 3) * 4
    }

    var checksumBitCount: Int {
        entropyByteCount / 4
    }
}
