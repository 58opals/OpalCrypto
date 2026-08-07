// OpalCrypto.Nostr.NIP44~KeyDerivation.swift

import Foundation

extension OpalCrypto.Nostr.NIP44 {
    /// Derives the symmetric NIP-44 conversation key for two x-only identities.
    public static func deriveConversationKey(
        signingKey: OpalCrypto.Secp256k1.SigningKey,
        publicKey: OpalCrypto.Signature.BIP340.VerificationKey
    ) -> ConversationKey {
        let secp256k1PublicKey = OpalCrypto.Secp256k1.PublicKey(
            parsedPublicKeyModel: ParsedPublicKeyModel(
                affinePoint: publicKey.verificationKeyModel.affinePoint
            )
        )
        let sharedPointXCoordinate =
            OpalCrypto.Secp256k1.deriveSharedPointXCoordinate(
                signingKey: signingKey,
                publicKey: secp256k1PublicKey
            )
        return ConversationKey(
            validatedRawRepresentation:
                NostrImplementationPossibility44Model
                    .deriveConversationKey(
                        sharedPointXCoordinate:
                            sharedPointXCoordinate.rawRepresentation
                    )
        )
    }
}
