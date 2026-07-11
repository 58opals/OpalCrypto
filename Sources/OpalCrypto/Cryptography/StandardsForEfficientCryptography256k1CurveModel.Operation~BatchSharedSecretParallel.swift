// StandardsForEfficientCryptography256k1CurveModel.Operation~BatchSharedSecretParallel.swift

import Foundation

extension StandardsForEfficientCryptography256k1CurveModel.Operation {
    static func deriveSharedSecretsInParallel(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        parsedPublicKeyModels: [ParsedPublicKeyModel],
        chunkSize: Int
    ) async throws -> [Data] {
        try Task.checkCancellation()
        let totalCount = parsedPublicKeyModels.count
        let chunkCount = (totalCount + chunkSize - 1) / chunkSize
        return try await withThrowingTaskGroup(of: (Int, [Data]).self) { group in
            for chunkIndex in 0..<chunkCount {
                try Task.checkCancellation()
                let startIndex = chunkIndex * chunkSize
                let endIndex = min(startIndex + chunkSize, totalCount)

                group.addTask {
                    try Task.checkCancellation()
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
                try Task.checkCancellation()
                chunkResults[chunkIndex] = sharedSecrets
            }

            try Task.checkCancellation()
            var sharedSecrets: [Data] = .init()
            sharedSecrets.reserveCapacity(totalCount)
            for chunkResult in chunkResults {
                guard let chunkResult else {
                    throw Error.invalidDerivedPublicKey
                }
                sharedSecrets.append(contentsOf: chunkResult)
            }
            try Task.checkCancellation()
            return sharedSecrets
        }
    }

    static func deriveSharedSecretsInParallel(
        scalarPlan: SharedSecretScalarMultiplicationPlan,
        publicKeys: [OpalCrypto.Secp256k1.PublicKey],
        chunkSize: Int
    ) async throws -> [Data] {
        try Task.checkCancellation()
        let totalCount = publicKeys.count
        let chunkCount = (totalCount + chunkSize - 1) / chunkSize
        return try await withThrowingTaskGroup(of: (Int, [Data]).self) { group in
            for chunkIndex in 0..<chunkCount {
                try Task.checkCancellation()
                let startIndex = chunkIndex * chunkSize
                let endIndex = min(startIndex + chunkSize, totalCount)

                group.addTask {
                    try Task.checkCancellation()
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
                try Task.checkCancellation()
                chunkResults[chunkIndex] = sharedSecrets
            }

            try Task.checkCancellation()
            var sharedSecrets: [Data] = .init()
            sharedSecrets.reserveCapacity(totalCount)
            for chunkResult in chunkResults {
                guard let chunkResult else {
                    throw Error.invalidDerivedPublicKey
                }
                sharedSecrets.append(contentsOf: chunkResult)
            }
            try Task.checkCancellation()
            return sharedSecrets
        }
    }
}
