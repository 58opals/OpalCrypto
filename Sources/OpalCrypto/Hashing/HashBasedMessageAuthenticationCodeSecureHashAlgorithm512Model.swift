// HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model.swift

import Foundation
import CryptoKit

internal struct HashBasedMessageAuthenticationCodeSecureHashAlgorithm512Model {
    internal static func hash(_ data: Data, key: Data) -> Data {
        let input = data
        let key = key
        let hmac = HMAC<CryptoKit.SHA512>.authenticationCode(for: input, using: .init(data: key))
        return Data(hmac)
    }
}
