// PerformanceOptimizationBatchDerivationValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite("Performance optimization batch-derivation validation")
struct PerformanceOptimizationBatchDerivationValidator {
    @Test("Batch compressed public-key derivation preserves ordering in the parallel path")
    func batchCompressedPublicKeyDerivationPreservesOrderingInTheParallelPath() async throws {
        let privateKeys = OpalCryptoTestSupport.makePrivateKeys(count: 256)
        let typedPrivateKeys = try privateKeys.map {
            try OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: $0)
        }
        let batchPublicKeys = try await OpalCrypto.Secp256k1.derivePublicKeys(
            from: typedPrivateKeys
        )
        let singlePublicKeys = try typedPrivateKeys.map {
            try OpalCrypto.Secp256k1.derivePublicKey(from: $0)
        }

        #expect(batchPublicKeys.map(\.rawRepresentation) == singlePublicKeys.map(\.rawRepresentation))
    }

    @Test("Batch compressed public-key derivation from parsed scalars matches data-based and single-key derivation")
    func batchCompressedPublicKeyDerivationFromParsedScalarsMatchesDataBasedAndSingleKeyDerivation()
        async throws {
        let privateKeys = OpalCryptoTestSupport.makePrivateKeys(count: 256)
        let privateKeyScalars = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parsePrivateKeyScalars(
                fromPrivateKeys32: privateKeys,
                assumingValidPrivateKeys: false
            )
        let scalarBatchPublicKeys = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeyScalars: privateKeyScalars,
                executionMode: .automatic
            )
        let dataBatchPublicKeys = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys,
                executionMode: .automatic
            )
        let singlePublicKeys = try privateKeys.map {
            try OpalCrypto.Secp256k1.derivePublicKey(
                from: OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: $0)
            ).rawRepresentation
        }

        #expect(scalarBatchPublicKeys == dataBatchPublicKeys)
        #expect(scalarBatchPublicKeys == singlePublicKeys)
    }

    @Test("Global affine conversion after batch Jacobian multiplication matches single derivation at 256-key scale")
    func globalAffineConversionAfterBatchJacobianMultiplicationMatchesSingleDerivationAt256KeyScale()
        throws {
        let privateKeys = OpalCryptoTestSupport.makePrivateKeys(count: 256)
        let privateKeyScalars = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parsePrivateKeyScalars(
                fromPrivateKeys32: privateKeys,
                assumingValidPrivateKeys: false
            )
        let jacobianPoints = StandardsForEfficientCryptography256k1CurveModel.Operation
            .derivePublicKeyJacobianPoints(fromPrivateKeyScalars: privateKeyScalars)
        let batchPublicKeys = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .encodeCompressedPublicKeys(fromJacobianPoints: jacobianPoints)
        let singlePublicKeys = try privateKeys.map {
            try OpalCrypto.Secp256k1.derivePublicKey(
                from: OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: $0)
            ).rawRepresentation
        }

        #expect(batchPublicKeys == singlePublicKeys)
    }

    @Test("Forced serial and forced parallel batch derivation return identical ordered results at 256-key scale")
    func forcedSerialAndForcedParallelBatchDerivationReturnIdenticalOrderedResultsAt256KeyScale()
        async throws {
        let privateKeys = OpalCryptoTestSupport.makePrivateKeys(count: 256)

        let forcedSerialPublicKeys = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys,
                executionMode: .serial
            )
        let forcedParallelPublicKeys = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys,
                executionMode: .parallel
            )

        #expect(forcedSerialPublicKeys == forcedParallelPublicKeys)
    }

    @Test("Automatic batch derivation matches forced parallel results at the 256-key threshold")
    func automaticBatchDerivationMatchesForcedParallelResultsAtThe256KeyThreshold() async throws {
        let privateKeys256 = OpalCryptoTestSupport.makePrivateKeys(count: 256)

        let automaticPublicKeys256 = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys256,
                executionMode: .automatic
            )
        let forcedParallelPublicKeys256 = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys256,
                executionMode: .parallel
            )

        #expect(automaticPublicKeys256 == forcedParallelPublicKeys256)
    }
}
