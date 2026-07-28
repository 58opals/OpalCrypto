// HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model.swift

import CryptoKit
import Foundation

enum HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model {
    static func hash<Input: DataProtocol>(_ input: Input, key: Data) -> Data {
        let authenticationCode = HMAC<CryptoKit.SHA256>.authenticationCode(
            for: input,
            using: .init(data: key)
        )
        return Data(authenticationCode)
    }
}
