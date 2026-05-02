// PerformanceSmokeValidator.swift

import Foundation
import Testing
@testable import OpalCrypto

@Suite(
    "Performance smoke validation",
    .tags(.performanceSmoke),
    .enabled(if: OpalCryptoTestSupport.isPerformanceSmokeEnabled)
)
struct PerformanceSmokeValidator {
    @Test("Global affine conversion after batch Jacobian multiplication matches single derivation at 1024-key scale")
    func globalAffineConversionAfterBatchJacobianMultiplicationMatchesSingleDerivationAt1024KeyScale()
        throws {
        let privateKeys = OpalCryptoTestSupport.makePrivateKeys(count: 1024)
        let privateKeyScalars = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .parsePrivateKeyScalars(
                fromPrivateKeys32: privateKeys,
                assumingValidPrivateKeys: false
            )
        let jacobianPoints = StandardsForEfficientCryptography256k1CurveModel.Operation
            .derivePublicKeyJacobianPoints(
                fromPrivateKeyScalars: privateKeyScalars
            )
        let batchPublicKeys = try StandardsForEfficientCryptography256k1CurveModel.Operation
            .encodeCompressedPublicKeys(fromJacobianPoints: jacobianPoints)
        let singlePublicKeys = try privateKeys.map {
            try OpalCrypto.Secp256k1.derivePublicKey(
                from: OpalCrypto.Secp256k1.PrivateKey(rawRepresentation: $0)
            ).rawRepresentation
        }

        #expect(batchPublicKeys == singlePublicKeys)
    }

    @Test("Forced serial and forced parallel batch derivation return identical ordered results at 1024-key scale")
    func forcedSerialAndForcedParallelBatchDerivationReturnIdenticalOrderedResultsAt1024KeyScale()
        async throws {
        let privateKeys = OpalCryptoTestSupport.makePrivateKeys(count: 1024)

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

    @Test("Automatic batch derivation matches forced parallel results at the 1024-key threshold")
    func automaticBatchDerivationMatchesForcedParallelResultsAtThe1024KeyThreshold()
        async throws {
        let privateKeys1024 = OpalCryptoTestSupport.makePrivateKeys(count: 1024)

        let automaticPublicKeys1024 = try await StandardsForEfficientCryptography256k1CurveModel
            .Operation.deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys1024,
                executionMode: .automatic
            )
        let forcedParallelPublicKeys1024 =
            try await StandardsForEfficientCryptography256k1CurveModel.Operation
            .deriveCompressedPublicKeys(
                fromPrivateKeys32: privateKeys1024,
                executionMode: .parallel
            )

        #expect(automaticPublicKeys1024 == forcedParallelPublicKeys1024)
    }
}
