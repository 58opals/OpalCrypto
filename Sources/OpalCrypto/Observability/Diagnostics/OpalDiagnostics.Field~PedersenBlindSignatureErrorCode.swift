// OpalDiagnostics.Field~PedersenBlindSignatureErrorCode.swift

import OpalDiagnostics

extension OpalDiagnostics.Field {
    static func pedersenErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.Pedersen.Error.invalidAlternateBasePointLength:
            OpalDiagnostics.ErrorCode.invalidAlternateBasePointLength
        case OpalCrypto.Pedersen.Error.invalidAlternateBasePointPrefix:
            OpalDiagnostics.ErrorCode.invalidAlternateBasePointPrefix
        case OpalCrypto.Pedersen.Error.invalidAlternateBasePoint:
            OpalDiagnostics.ErrorCode.invalidAlternateBasePoint
        case OpalCrypto.Pedersen.Error.insecureAlternateBasePoint:
            OpalDiagnostics.ErrorCode.insecureAlternateBasePoint
        case OpalCrypto.Pedersen.Error.invalidNonceLength:
            OpalDiagnostics.ErrorCode.invalidNonceLength
        case OpalCrypto.Pedersen.Error.invalidNonce:
            OpalDiagnostics.ErrorCode.invalidNonce
        case OpalCrypto.Pedersen.Error.invalidCommitmentLength:
            OpalDiagnostics.ErrorCode.invalidCommitmentLength
        case OpalCrypto.Pedersen.Error.invalidCommitment:
            OpalDiagnostics.ErrorCode.invalidCommitment
        case OpalCrypto.Pedersen.Error.emptyCommitmentList:
            OpalDiagnostics.ErrorCode.emptyCommitmentList
        case OpalCrypto.Pedersen.Error.mismatchedSetup:
            OpalDiagnostics.ErrorCode.mismatchedSetup
        case OpalCrypto.Pedersen.Error.cryptographyFailure:
            OpalDiagnostics.ErrorCode.cryptographyFailure
        default:
            nil
        }
    }

    static func blindSignatureErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.BlindSignature.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.BlindSignature.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.BlindSignature.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey
        case OpalCrypto.BlindSignature.Error.invalidNoncePointLength:
            OpalDiagnostics.ErrorCode.invalidNoncePointLength
        case OpalCrypto.BlindSignature.Error.invalidNoncePointPrefix:
            OpalDiagnostics.ErrorCode.invalidNoncePointPrefix
        case OpalCrypto.BlindSignature.Error.invalidNoncePoint:
            OpalDiagnostics.ErrorCode.invalidNoncePoint
        case OpalCrypto.BlindSignature.Error.invalidDigestLength:
            OpalDiagnostics.ErrorCode.invalidDigestLength
        case OpalCrypto.BlindSignature.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.BlindSignature.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey
        case OpalCrypto.BlindSignature.Error.invalidRequestLength:
            OpalDiagnostics.ErrorCode.invalidRequestLength
        case OpalCrypto.BlindSignature.Error.invalidRequestScalar:
            OpalDiagnostics.ErrorCode.invalidRequestScalar
        case OpalCrypto.BlindSignature.Error.invalidResponseLength:
            OpalDiagnostics.ErrorCode.invalidResponseLength
        case OpalCrypto.BlindSignature.Error.invalidResponseScalar:
            OpalDiagnostics.ErrorCode.invalidResponseScalar
        case OpalCrypto.BlindSignature.Error.nonceAlreadyUsed:
            OpalDiagnostics.ErrorCode.nonceAlreadyUsed
        case OpalCrypto.BlindSignature.Error.cryptographyFailure:
            OpalDiagnostics.ErrorCode.cryptographyFailure
        case OpalCrypto.BlindSignature.Error.verificationFailed:
            OpalDiagnostics.ErrorCode.verificationFailed
        default:
            nil
        }
    }
}
