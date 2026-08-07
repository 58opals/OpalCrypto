// OpalCrypto.RSABSSA.Signature~Verification.swift

import Foundation

extension OpalCrypto.RSABSSA.Signature {
    /// Verifies this signature over randomized preparation of `message`.
    public func verify(
        message: Data,
        messageRandomizer: OpalCrypto.RSABSSA.MessageRandomizer,
        using verificationKey: OpalCrypto.RSABSSA.VerificationKey
    ) -> Bool {
        var preparedMessage = messageRandomizer.rawRepresentation
        preparedMessage.append(message)
        return RSABSSAModel.verify(
            signature: rawRepresentation,
            preparedMessage: preparedMessage,
            verificationKey: verificationKey.model
        )
    }
}
