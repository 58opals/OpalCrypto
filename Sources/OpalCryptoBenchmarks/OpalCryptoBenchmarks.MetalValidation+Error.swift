// OpalCryptoBenchmarks.MetalValidation+Error.swift

extension OpalCryptoBenchmarks.MetalValidation {
    enum Error: Swift.Error {
        case invalidHex
        case unexpectedResult(String)
    }
}
