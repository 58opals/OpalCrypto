// NostrImplementationPossibility44Model~KeyDerivation.swift

import Foundation

extension NostrImplementationPossibility44Model {
    static func deriveMessageKeys(
        conversationKey: Data,
        nonce: Data
    ) -> MessageKeys {
        precondition(conversationKey.count == 32)
        precondition(nonce.count == nonceByteCount)
        let expandedKey = expandKey(
            pseudorandomKey: conversationKey,
            information: nonce,
            outputByteCount: 76
        )
        return MessageKeys(
            chachaKey: Data(expandedKey[0 ..< 32]),
            chachaNonce: Data(expandedKey[32 ..< 44]),
            authenticationKey: Data(expandedKey[44 ..< 76])
        )
    }

    private static func expandKey(
        pseudorandomKey: Data,
        information: Data,
        outputByteCount: Int
    ) -> Data {
        var output = Data()
        output.reserveCapacity(outputByteCount)
        var previousBlock = Data()
        var counter: UInt8 = 1

        while output.count < outputByteCount {
            var blockInput = previousBlock
            blockInput.append(information)
            blockInput.append(counter)
            previousBlock =
                HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model
                    .hash(blockInput, key: pseudorandomKey)
            output.append(previousBlock)
            counter &+= 1
        }
        return Data(output.prefix(outputByteCount))
    }

    static func authenticationCode(
        ciphertext: Data,
        nonce: Data,
        key: Data
    ) -> Data {
        var authenticatedData = nonce
        authenticatedData.append(ciphertext)
        return HashBasedMessageAuthenticationCodeSecureHashAlgorithm256Model
            .hash(authenticatedData, key: key)
    }
}
