// SchnorrBatchVerificationOperation~Policy.swift

import Foundation

extension SchnorrBatchVerificationOperation {
    static func selectBackend(
        recordCount: Int,
        policy: OpalCrypto.BatchExecutionPolicy
    ) async -> SchnorrBatchVerificationBackend {
        guard recordCount > 0 else { return .cpu }
        switch policy.executionMode {
        case .cpu:
            return .cpu
        case .metal:
            return .metal
        case .automatic:
            return await shouldUseAutomaticMetal(recordCount: recordCount)
                ? .metal
                : .cpu
        }
    }

    static func shouldUseAutomaticMetal(recordCount: Int) async -> Bool {
        guard MetalSchnorrBatchVerificationClient.isCertifiedDeviceAvailable,
              !ProcessInfo.processInfo.isLowPowerModeEnabled,
              ProcessInfo.processInfo.thermalState != .serious,
              ProcessInfo.processInfo.thermalState != .critical
        else {
            return false
        }
        let isRuntimeWarm = await MetalSchnorrBatchVerificationClient.shared
            .isRuntimeWarm
        return meetsAutomaticMetalThreshold(
            recordCount: recordCount,
            isRuntimeWarm: isRuntimeWarm
        )
    }

    static func meetsAutomaticMetalThreshold(
        recordCount: Int,
        isRuntimeWarm: Bool
    ) -> Bool {
        let threshold = isRuntimeWarm
            ? minimumWarmAutomaticMetalRecordCount
            : minimumColdAutomaticMetalRecordCount
        return recordCount >= threshold
    }

    static func normalize(
        _ input: SchnorrBatchVerificationInput
    ) -> SchnorrBatchVerificationInput {
        guard case .varying(let publicKeys) = input.keyInput,
              let verificationKeyModel = makeUniformVerificationKeyModel(
                  publicKeys: publicKeys
              )
        else {
            return input
        }
        return SchnorrBatchVerificationInput(
            signatures: input.signatures,
            digests: input.digests,
            verificationKey: OpalCrypto.Signature.VerificationKey(
                verificationKeyModel: verificationKeyModel
            )
        )
    }

    static var emptyExecutionResult: SchnorrBatchVerificationExecutionResult {
        SchnorrBatchVerificationExecutionResult(
            results: [],
            backend: .cpu,
            chunkCount: 0,
            cpuPreparationDuration: nil,
            gpuExecutionDuration: nil,
            readbackDuration: nil
        )
    }

    static func makePublicError(
        _ error: Swift.Error,
        policy: OpalCrypto.BatchExecutionPolicy
    ) -> Swift.Error {
        if let error = error as? OpalCrypto.Signature.Schnorr.VerificationBatch.Error {
            return error
        }
        switch error {
        case MetalSchnorrBatchVerificationError.unavailable,
             MetalSchnorrBatchVerificationError.uncertifiedDevice:
            return OpalCrypto.Signature.Schnorr.VerificationBatch.Error
                .executionUnavailable(policy: policy)
        case is MetalSchnorrBatchVerificationError:
            return OpalCrypto.Signature.Schnorr.VerificationBatch.Error
                .executionFailed(policy: policy)
        default:
            return OpalCrypto.Signature.Schnorr.VerificationBatch.Error
                .executionFailed(policy: policy)
        }
    }
}
