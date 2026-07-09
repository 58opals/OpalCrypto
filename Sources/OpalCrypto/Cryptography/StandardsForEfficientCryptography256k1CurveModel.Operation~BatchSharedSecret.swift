// StandardsForEfficientCryptography256k1CurveModel.Operation~BatchSharedSecret.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    enum SharedSecretBatchDerivationExecutionMode {
        case automatic
        case serial
        case parallel
    }

    static func deriveSharedSecrets(
        privateKeyData32Bytes: Data,
        publicKeys: [Data],
        executionMode: SharedSecretBatchDerivationExecutionMode = .automatic
    ) async throws -> [Data] {
        guard !publicKeys.isEmpty else { return .init() }
        let parsedPublicKeys = try publicKeys.map { publicKey in
            ParsedPublicKeyModel(
                affinePoint: try parsePublicKeyAffine(publicKey)
            )
        }
        return try await deriveSharedSecrets(
            privateKeyData32Bytes: privateKeyData32Bytes,
            parsedPublicKeyModels: parsedPublicKeys,
            executionMode: executionMode
        )
    }

    static func deriveSharedSecrets(
        privateKeyData32Bytes: Data,
        parsedPublicKeyModels: [ParsedPublicKeyModel],
        executionMode: SharedSecretBatchDerivationExecutionMode = .automatic
    ) async throws -> [Data] {
        guard !parsedPublicKeyModels.isEmpty else { return .init() }
        let privateKeyScalar = try parsePrivateKeyScalar(
            privateKeyData32Bytes,
            requireNonZero: true
        )
        let scalarPlan = SharedSecretScalarMultiplicationPlan(
            privateKeyScalar: privateKeyScalar
        )
        return try await deriveSharedSecrets(
            scalarPlan: scalarPlan,
            parsedPublicKeyModels: parsedPublicKeyModels,
            executionMode: executionMode
        )
    }

    static func deriveSharedSecrets(
        privateKey: OpalCrypto.Secp256k1.PrivateKey,
        publicKeys: [OpalCrypto.Secp256k1.PublicKey],
        executionMode: SharedSecretBatchDerivationExecutionMode = .automatic
    ) async throws -> [Data] {
        guard !publicKeys.isEmpty else { return .init() }
        let privateKeyScalar = try parsePrivateKeyScalarUnchecked(
            privateKey.rawRepresentation,
            requireNonZero: true
        )
        let scalarPlan = SharedSecretScalarMultiplicationPlan(
            privateKeyScalar: privateKeyScalar
        )
        return try await deriveSharedSecrets(
            scalarPlan: scalarPlan,
            publicKeys: publicKeys,
            executionMode: executionMode
        )
    }

    static func deriveSharedSecret(
        privateKeyScalar: ScalarModel,
        publicKeyAffine: AffinePointModel
    ) throws -> Data {
        try deriveSharedSecret(
            scalarPlan: SharedSecretScalarMultiplicationPlan(privateKeyScalar: privateKeyScalar),
            verificationKeyModel: VerificationKeyModel(affinePoint: publicKeyAffine)
        )
    }
}

private struct SharedSecretScalarMultiplicationPlan: Sendable {
    let primaryDigits: SignedScalar128Model.WindowedNonAdjacentForm
    let secondaryDigits: SignedScalar128Model.WindowedNonAdjacentForm

    init(privateKeyScalar: ScalarModel) {
        let scalarSplit = privateKeyScalar.splitForEndomorphism()
        primaryDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            scalarSplit.firstScalar,
            width: ScalarMultiplicationModel.verificationKeyWindowedNonAdjacentFormWidth
        )
        secondaryDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            scalarSplit.secondScalar,
            width: ScalarMultiplicationModel.verificationKeyWindowedNonAdjacentFormWidth
        )
    }
}

private extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static let minimumAutomaticParallelSharedSecretCount = 256
    static let minimumSharedSecretsPerTask = 128
    static let minimumAutomaticParallelSharedSecretTaskCount = 4

    static func deriveSharedSecrets(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        parsedPublicKeyModels: [ParsedPublicKeyModel],
        executionMode: SharedSecretBatchDerivationExecutionMode
    ) async throws -> [Data] {
        let taskCount = sharedSecretBatchTaskCount(
            totalCount: parsedPublicKeyModels.count,
            executionMode: executionMode
        )
        guard taskCount >= 2 else {
            return try deriveSharedSecrets(
                scalarPlan: scalarPlan,
                parsedPublicKeyModels: parsedPublicKeyModels,
                startIndex: 0,
                endIndex: parsedPublicKeyModels.count
            )
        }
        let chunkSize = (parsedPublicKeyModels.count + taskCount - 1) / taskCount
        return try await deriveSharedSecretsInParallel(
            scalarPlan: scalarPlan,
            parsedPublicKeyModels: parsedPublicKeyModels,
            chunkSize: chunkSize
        )
    }

    static func deriveSharedSecrets(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        publicKeys: [OpalCrypto.Secp256k1.PublicKey],
        executionMode: SharedSecretBatchDerivationExecutionMode
    ) async throws -> [Data] {
        let taskCount = sharedSecretBatchTaskCount(
            totalCount: publicKeys.count,
            executionMode: executionMode
        )
        guard taskCount >= 2 else {
            return try deriveSharedSecrets(
                scalarPlan: scalarPlan,
                publicKeys: publicKeys,
                startIndex: 0,
                endIndex: publicKeys.count
            )
        }
        let chunkSize = (publicKeys.count + taskCount - 1) / taskCount
        return try await deriveSharedSecretsInParallel(
            scalarPlan: scalarPlan,
            publicKeys: publicKeys,
            chunkSize: chunkSize
        )
    }

    static func sharedSecretBatchTaskCount(
        totalCount: Int,
        executionMode: SharedSecretBatchDerivationExecutionMode
    ) -> Int {
        guard totalCount > 0 else { return 0 }

        let processorCount = max(1, ProcessInfo.processInfo.activeProcessorCount)
        switch executionMode {
        case .automatic:
            guard totalCount >= minimumAutomaticParallelSharedSecretCount else {
                return 1
            }
            if totalCount == minimumAutomaticParallelSharedSecretCount {
                return min(processorCount, minimumAutomaticParallelSharedSecretTaskCount)
            }
            return parallelSharedSecretBatchTaskCount(
                totalCount: totalCount,
                processorCount: processorCount
            )
        case .serial:
            return 1
        case .parallel:
            return parallelSharedSecretBatchTaskCount(
                totalCount: totalCount,
                processorCount: processorCount
            )
        }
    }

    static func parallelSharedSecretBatchTaskCount(
        totalCount: Int,
        processorCount: Int
    ) -> Int {
        let targetTaskCount = max(2, (totalCount + minimumSharedSecretsPerTask - 1) / minimumSharedSecretsPerTask)
        return min(processorCount, targetTaskCount)
    }

    static func deriveSharedSecretsInParallel(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        parsedPublicKeyModels: [ParsedPublicKeyModel],
        chunkSize: Int
    ) async throws -> [Data] {
        let totalCount = parsedPublicKeyModels.count
        let chunkCount = (totalCount + chunkSize - 1) / chunkSize
        return try await withThrowingTaskGroup(of: (Int, [Data]).self) { group in
            for chunkIndex in 0..<chunkCount {
                let startIndex = chunkIndex * chunkSize
                let endIndex = min(startIndex + chunkSize, totalCount)

                group.addTask {
                    let sharedSecrets = try deriveSharedSecrets(
                        scalarPlan: scalarPlan,
                        parsedPublicKeyModels: parsedPublicKeyModels,
                        startIndex: startIndex,
                        endIndex: endIndex
                    )
                    return (chunkIndex, sharedSecrets)
                }
            }

            var chunkResults = Array<[Data]?>(repeating: nil, count: chunkCount)

            for try await (chunkIndex, sharedSecrets) in group {
                chunkResults[chunkIndex] = sharedSecrets
            }

            var sharedSecrets: [Data] = .init()
            sharedSecrets.reserveCapacity(totalCount)
            for chunkResult in chunkResults {
                guard let chunkResult else {
                    throw Error.invalidDerivedPublicKey
                }
                sharedSecrets.append(contentsOf: chunkResult)
            }
            return sharedSecrets
        }
    }

    static func deriveSharedSecretsInParallel(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        publicKeys: [OpalCrypto.Secp256k1.PublicKey],
        chunkSize: Int
    ) async throws -> [Data] {
        let totalCount = publicKeys.count
        let chunkCount = (totalCount + chunkSize - 1) / chunkSize
        return try await withThrowingTaskGroup(of: (Int, [Data]).self) { group in
            for chunkIndex in 0..<chunkCount {
                let startIndex = chunkIndex * chunkSize
                let endIndex = min(startIndex + chunkSize, totalCount)

                group.addTask {
                    let sharedSecrets = try deriveSharedSecrets(
                        scalarPlan: scalarPlan,
                        publicKeys: publicKeys,
                        startIndex: startIndex,
                        endIndex: endIndex
                    )
                    return (chunkIndex, sharedSecrets)
                }
            }

            var chunkResults = Array<[Data]?>(repeating: nil, count: chunkCount)

            for try await (chunkIndex, sharedSecrets) in group {
                chunkResults[chunkIndex] = sharedSecrets
            }

            var sharedSecrets: [Data] = .init()
            sharedSecrets.reserveCapacity(totalCount)
            for chunkResult in chunkResults {
                guard let chunkResult else {
                    throw Error.invalidDerivedPublicKey
                }
                sharedSecrets.append(contentsOf: chunkResult)
            }
            return sharedSecrets
        }
    }

    static func deriveSharedSecrets(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        parsedPublicKeyModels: [ParsedPublicKeyModel],
        startIndex: Int,
        endIndex: Int
    ) throws -> [Data] {
        var sharedSecrets: [Data] = .init()
        sharedSecrets.reserveCapacity(endIndex - startIndex)
        for index in startIndex..<endIndex {
            let verificationKeyModel = VerificationKeyModel(
                parsedPublicKeyModel: parsedPublicKeyModels[index]
            )
            sharedSecrets.append(
                try deriveSharedSecret(
                    scalarPlan: scalarPlan,
                    verificationKeyModel: verificationKeyModel
                )
            )
        }
        return sharedSecrets
    }

    static func deriveSharedSecrets(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        publicKeys: [OpalCrypto.Secp256k1.PublicKey],
        startIndex: Int,
        endIndex: Int
    ) throws -> [Data] {
        var sharedSecrets: [Data] = .init()
        sharedSecrets.reserveCapacity(endIndex - startIndex)
        for index in startIndex..<endIndex {
            let verificationKeyModel = VerificationKeyModel(
                parsedPublicKeyModel: publicKeys[index].parsedPublicKeyModel
            )
            sharedSecrets.append(
                try deriveSharedSecret(
                    scalarPlan: scalarPlan,
                    verificationKeyModel: verificationKeyModel
                )
            )
        }
        return sharedSecrets
    }

    static func deriveSharedSecret(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        verificationKeyModel: VerificationKeyModel
    ) throws -> Data {
        let sharedPoint = ScalarMultiplicationModel.multiplyWindowedDigits(
            primaryDigits: scalarPlan.primaryDigits,
            primaryTable: verificationKeyModel.oddMultiplesAffine,
            secondaryDigits: scalarPlan.secondaryDigits,
            secondaryTable: verificationKeyModel.endomorphismOddMultiplesAffine
        )
        guard let sharedAffine = sharedPoint.convertToAffine() else {
            throw Error.invalidDerivedPublicKey
        }
        return SecureHashAlgorithm256Model.hash(sharedAffine.encodeCompressed33())
    }
}
