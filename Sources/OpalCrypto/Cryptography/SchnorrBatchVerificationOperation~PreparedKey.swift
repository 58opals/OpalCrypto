// SchnorrBatchVerificationOperation~PreparedKey.swift

extension SchnorrBatchVerificationOperation {
    static func verifyPreparedKeysSerialUsingCPU(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeys: [OpalCrypto.Signature.VerificationKey]
    ) throws -> [Bool] {
        try verifyPreparedKeyRange(
            signatures: signatures,
            digests: digests,
            verificationKeys: verificationKeys,
            startIndex: 0,
            endIndex: signatures.count
        )
    }

    static func verifyPreparedKeysUsingCPU(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeys: [OpalCrypto.Signature.VerificationKey]
    ) async throws -> [Bool] {
        try await verifyInParallel(recordCount: signatures.count) {
            startIndex,
            endIndex in
            try verifyPreparedKeyRange(
                signatures: signatures,
                digests: digests,
                verificationKeys: verificationKeys,
                startIndex: startIndex,
                endIndex: endIndex
            )
        }
    }

    private static func verifyPreparedKeyRange(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeys: [OpalCrypto.Signature.VerificationKey],
        startIndex: Int,
        endIndex: Int
    ) throws -> [Bool] {
        var results: [Bool] = []
        results.reserveCapacity(endIndex - startIndex)
        for index in startIndex..<endIndex {
            if (index - startIndex).isMultiple(of: 32) {
                try Task.checkCancellation()
            }
            results.append(
                try SchnorrSignatureModel.verify(
                    signature: signatures[index].signatureModel,
                    digestData32Bytes: digests[index].rawRepresentation,
                    verificationKeyModel: verificationKeys[index].verificationKeyModel
                )
            )
        }
        return results
    }
}
