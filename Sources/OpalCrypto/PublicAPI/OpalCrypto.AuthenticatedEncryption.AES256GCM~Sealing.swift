// OpalCrypto.AuthenticatedEncryption.AES256GCM~Sealing.swift

import Foundation

extension OpalCrypto.AuthenticatedEncryption.AES256GCM {
    /// Seals plaintext with a securely generated 96-bit nonce.
    public static func seal(
        _ plaintext: Data,
        using key: Key,
        authenticating authenticatedData: Data
    ) throws -> SealedBox {
        try seal(
            plaintext,
            using: key,
            authenticating: authenticatedData,
            nonce: .generate()
        )
    }

    /// Seals plaintext with an explicit 96-bit nonce.
    ///
    /// This entry point supports conformance vectors and injected secure-random
    /// dependencies. Never reuse `nonce` with the same key.
    public static func seal(
        _ plaintext: Data,
        using key: Key,
        authenticating authenticatedData: Data,
        nonce: Nonce
    ) throws -> SealedBox {
        do {
            return SealedBox(
                validatedCombinedRepresentation:
                    try AdvancedEncryptionStandard256GaloisCounterModeModel.seal(
                        plaintext,
                        key: key.rawRepresentation,
                        authenticatedData: authenticatedData,
                        nonce: nonce.rawRepresentation
                    )
            )
        } catch {
            throw Error.sealingFailed
        }
    }

    /// Authenticates and opens a combined AES-GCM sealed box.
    public static func open(
        _ sealedBox: SealedBox,
        using key: Key,
        authenticating authenticatedData: Data
    ) throws -> Data {
        do {
            return try AdvancedEncryptionStandard256GaloisCounterModeModel.open(
                sealedBox.combinedRepresentation,
                key: key.rawRepresentation,
                authenticatedData: authenticatedData
            )
        } catch let error as AdvancedEncryptionStandard256GaloisCounterModeModel.Error {
            switch error {
            case .invalidSealedBox:
                throw Error.malformedSealedBox
            case .authenticationFailed:
                throw Error.authenticationFailed
            case .sealingFailed:
                throw Error.sealingFailed
            }
        }
    }
}
