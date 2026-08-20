// OpalCrypto.RSABSSA.BlindRequest+RecoveryState.swift

import Foundation

extension OpalCrypto.RSABSSA.BlindRequest {
    /// Sensitive, versioned client state needed to restore one exact RFC 9474 request.
    ///
    /// The raw representation contains the message randomizer, PSS salt, and RSA blinding
    /// factor. It is not a public transcript and must be protected by application-owned
    /// authenticated encryption, one-attempt access control, and terminal erasure.
    public struct RecoveryState: Sendable, Equatable {
        private static let version: UInt8 = 1
        private static let verificationKeyIdentifierByteCount = 32
        private static let messageDigestByteCount = 32
        private static let messageRandomizerByteCount = 32
        private static let saltByteCount = 48
        private static let blindingFactorByteCount = 256

        /// The fixed width of the current versioned representation.
        public static let rawRepresentationByteCount =
            1
            + verificationKeyIdentifierByteCount
            + messageDigestByteCount
            + messageRandomizerByteCount
            + saltByteCount
            + blindingFactorByteCount

        public let rawRepresentation: Data

        let verificationKeyIdentifier: Data
        let messageDigest: Data
        let messageRandomizer: Data
        let salt: Data
        let blindingFactor: Data

        /// Parses the fixed-width recovery representation without using its secret material.
        /// Full message, key, PSS, and blinding validation occurs during request restoration.
        public init(rawRepresentation: Data) throws {
            let normalized = Data(rawRepresentation)
            guard normalized.count
                    == Self.rawRepresentationByteCount else {
                throw OpalCrypto.RSABSSA.Error
                    .invalidBlindRequestRecoveryStateLength(
                        expected: Self.rawRepresentationByteCount,
                        actual: normalized.count
                    )
            }
            guard normalized[normalized.startIndex]
                    == Self.version else {
                throw OpalCrypto.RSABSSA.Error
                    .unsupportedBlindRequestRecoveryStateVersion(
                        normalized[normalized.startIndex]
                    )
            }

            var offset = 1
            func take(_ count: Int) -> Data {
                defer { offset += count }
                return Data(normalized[offset ..< offset + count])
            }
            verificationKeyIdentifier = take(
                Self.verificationKeyIdentifierByteCount
            )
            messageDigest = take(Self.messageDigestByteCount)
            messageRandomizer = take(Self.messageRandomizerByteCount)
            salt = take(Self.saltByteCount)
            blindingFactor = take(Self.blindingFactorByteCount)
            self.rawRepresentation = normalized
        }

        init(material: RSABSSAModel.BlindRequestMaterial) {
            verificationKeyIdentifier = material.verificationKeyIdentifier
            messageDigest = material.messageDigest
            messageRandomizer = material.messageRandomizer
            salt = material.salt
            blindingFactor = material.blindingFactor

            var raw = Data([Self.version])
            raw.reserveCapacity(Self.rawRepresentationByteCount)
            raw.append(verificationKeyIdentifier)
            raw.append(messageDigest)
            raw.append(messageRandomizer)
            raw.append(salt)
            raw.append(blindingFactor)
            rawRepresentation = raw
        }
    }
}
