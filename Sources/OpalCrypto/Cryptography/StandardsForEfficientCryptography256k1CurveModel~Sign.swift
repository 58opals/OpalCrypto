// StandardsForEfficientCryptography256k1CurveModel~Sign.swift

import Foundation
import Security

internal extension StandardsForEfficientCryptography256k1CurveModel {
    static func sign(
        digestData32Bytes: Data,
        privateKeyData32Bytes: Data,
        nonce: NonceGenerationPolicy.EllipticCurveDigitalSignatureAlgorithmModel = .requestForComments6979SecureHashAlgorithm256,
        enforceLowS: Bool = true
    ) throws -> Signature {
        guard digestData32Bytes.count == 32 else {
            throw Error.invalidDigestLength(actual: digestData32Bytes.count)
        }
        guard privateKeyData32Bytes.count == 32 else {
            throw Error.invalidPrivateKeyLength(actual: privateKeyData32Bytes.count)
        }
        let privateKeyScalar: ScalarModel
        do {
            privateKeyScalar = try ScalarModel(data32: privateKeyData32Bytes, requireNonZero: true)
        } catch {
            throw Error.invalidPrivateKeyValue
        }
        let digestScalar = try ScalarConversionModel.makeReducedScalarFromDigest(digestData32Bytes)
        let makeNextNonce: () throws -> ScalarModel
        switch nonce {
        case .requestForComments6979SecureHashAlgorithm256:
            var generator = try NonceGeneratorModel.RequestForComments6979Model(
                privateKey: privateKeyScalar,
                digest32: digestData32Bytes
            )
            makeNextNonce = {
                try generator.makeNextScalar()
            }
        case .systemRandom:
            makeNextNonce = {
                try makeSystemRandomScalarForEllipticCurveDigitalSignatureAlgorithm()
            }
        }
        while true {
            let nonceScalar = try makeNextNonce()
            let noncePoint = ScalarMultiplicationModel.mulG(nonceScalar)
            guard let nonceAffine = noncePoint.convertToAffine() else {
                continue
            }
            guard let signatureRScalar = try? ScalarConversionModel.makeScalarFromFieldElement(nonceAffine.x) else {
                continue
            }
            guard !signatureRScalar.isZero else {
                continue
            }
            let nonceInverse = try nonceScalar.invert()
            let product = signatureRScalar.mulModN(privateKeyScalar)
            let sum = digestScalar.addModN(product)
            var signatureSScalar = nonceInverse.mulModN(sum)
            guard !signatureSScalar.isZero else {
                continue
            }
            if enforceLowS, signatureSScalar.compare(to: halfOrderScalar) == .orderedDescending {
                signatureSScalar = signatureSScalar.negateModN()
            }
            return try Signature(r: signatureRScalar.data32Bytes, s: signatureSScalar.data32Bytes)
        }
    }
}

private extension StandardsForEfficientCryptography256k1CurveModel {
    static func makeSystemRandomScalarForEllipticCurveDigitalSignatureAlgorithm() throws -> ScalarModel {
        while true {
            var data = Data(count: 32)
            let status = data.withUnsafeMutableBytes { buffer -> Int32 in
                guard let baseAddress = buffer.baseAddress else {
                    return errSecAllocate
                }
                return SecRandomCopyBytes(kSecRandomDefault, 32, baseAddress)
            }
            guard status == errSecSuccess else {
                throw Error.randomGenerationFailed(status: status)
            }
            if let scalar = try? ScalarModel(data32: data, requireNonZero: true) {
                return scalar
            }
        }
    }
}
