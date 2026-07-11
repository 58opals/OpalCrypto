// PerformanceBenchmarkOperations~SchnorrVerification.swift

import Foundation

extension PerformanceBenchmarkOperations {
    package static func verifySchnorrBatchSerial(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count
        )
        return try SchnorrBatchVerificationOperation.verifySerialUsingCPU(
            input: SchnorrBatchVerificationInput(
                signatures: signatures,
                digests: digests,
                verificationKey: verificationKey
            )
        ).map { $0 ? 1 : 0 }
    }

    package static func verifySchnorrBatchSerial(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeys: [OpalCrypto.Signature.VerificationKey]
    ) throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            verificationKeyCount: verificationKeys.count
        )
        return try SchnorrBatchVerificationOperation
            .verifyPreparedKeysSerialUsingCPU(
                signatures: signatures,
                digests: digests,
                verificationKeys: verificationKeys
            ).map { $0 ? 1 : 0 }
    }

    package static func verifySchnorrBatchSerial(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeyRawRepresentations: [Data]
    ) throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            verificationKeyCount: verificationKeyRawRepresentations.count
        )
        let publicKeys = try verificationKeyRawRepresentations.map {
            try OpalCrypto.Secp256k1.PublicKey(rawRepresentation: $0)
        }
        return try SchnorrBatchVerificationOperation.verifySerialUsingCPU(
            input: SchnorrBatchVerificationInput(
                signatures: signatures,
                digests: digests,
                publicKeys: publicKeys
            )
        ).map { $0 ? 1 : 0 }
    }

    package static func verifySchnorrBatchParallel(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKey: OpalCrypto.Signature.VerificationKey
    ) async throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count
        )
        return try await SchnorrBatchVerificationOperation.verifyUsingCPU(
            input: SchnorrBatchVerificationInput(
                signatures: signatures,
                digests: digests,
                verificationKey: verificationKey
            )
        ).map { $0 ? 1 : 0 }
    }

    package static func verifySchnorrBatchParallel(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeys: [OpalCrypto.Signature.VerificationKey]
    ) async throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            verificationKeyCount: verificationKeys.count
        )
        return try await SchnorrBatchVerificationOperation
            .verifyPreparedKeysUsingCPU(
                signatures: signatures,
                digests: digests,
                verificationKeys: verificationKeys
            )
            .map { $0 ? 1 : 0 }
    }

    package static func verifySchnorrBatchParallel(
        signatures: [OpalCrypto.Signature.Schnorr],
        digests: [OpalCrypto.Signature.Digest],
        verificationKeyRawRepresentations: [Data]
    ) async throws -> [UInt32] {
        try validateSchnorrBatchInputCounts(
            signatureCount: signatures.count,
            digestCount: digests.count,
            verificationKeyCount: verificationKeyRawRepresentations.count
        )
        let publicKeys = try verificationKeyRawRepresentations.map {
            try OpalCrypto.Secp256k1.PublicKey(rawRepresentation: $0)
        }
        return try await SchnorrBatchVerificationOperation.verifyUsingCPU(
            input: SchnorrBatchVerificationInput(
                signatures: signatures,
                digests: digests,
                publicKeys: publicKeys
            )
        ).map { $0 ? 1 : 0 }
    }

    private static func validateSchnorrBatchInputCounts(
        signatureCount: Int,
        digestCount: Int,
        verificationKeyCount: Int? = nil
    ) throws {
        guard signatureCount == digestCount,
              verificationKeyCount == nil || verificationKeyCount == signatureCount else {
            throw Error.mismatchedSchnorrBatchInputCounts(
                signatureCount: signatureCount,
                digestCount: digestCount,
                verificationKeyCount: verificationKeyCount
            )
        }
    }
}
