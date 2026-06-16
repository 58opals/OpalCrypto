// OpalDiagnostics.Field~KeyErrorCode.swift

import OpalDiagnostics

extension OpalDiagnostics.Field {
    static func keyDerivationErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.KeyDerivation.Error.invalidIterationCount:
            OpalDiagnostics.ErrorCode.invalidIterationCount
        case OpalCrypto.KeyDerivation.Error.emptySalt:
            OpalDiagnostics.ErrorCode.emptySalt
        case OpalCrypto.KeyDerivation.Error.invalidDerivedKeyLength:
            OpalDiagnostics.ErrorCode.invalidDerivedKeyLength
        case OpalCrypto.KeyDerivation.Error.derivedKeyLengthExceedsLimit:
            OpalDiagnostics.ErrorCode.derivedKeyLengthExceedsLimit
        default:
            nil
        }
    }

    static func mnemonicErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.Key.Mnemonic.Error.invalidWordCount:
            OpalDiagnostics.ErrorCode.invalidWordCount
        case OpalCrypto.Key.Mnemonic.Error.invalidEntropyLength:
            OpalDiagnostics.ErrorCode.invalidEntropyLength
        case OpalCrypto.Key.Mnemonic.Error.invalidWord:
            OpalDiagnostics.ErrorCode.invalidWord
        case OpalCrypto.Key.Mnemonic.Error.invalidChecksum:
            OpalDiagnostics.ErrorCode.invalidChecksum
        case OpalCrypto.Key.Mnemonic.Error.ambiguousLanguage:
            OpalDiagnostics.ErrorCode.ambiguousLanguage
        case OpalCrypto.Key.Mnemonic.Error.randomGenerationFailed:
            OpalDiagnostics.ErrorCode.randomGenerationFailed
        case OpalCrypto.Key.Mnemonic.Error.wordListResourceMissing:
            OpalDiagnostics.ErrorCode.wordListResourceMissing
        case OpalCrypto.Key.Mnemonic.Error.invalidWordList:
            OpalDiagnostics.ErrorCode.invalidWordList
        default:
            nil
        }
    }

    static func walletImportFormatErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.Key.WIF.Error.invalidBase58:
            OpalDiagnostics.ErrorCode.invalidBase58
        case OpalCrypto.Key.WIF.Error.invalidChecksum:
            OpalDiagnostics.ErrorCode.invalidChecksum
        case OpalCrypto.Key.WIF.Error.invalidPayloadLength:
            OpalDiagnostics.ErrorCode.invalidPayloadLength
        case OpalCrypto.Key.WIF.Error.invalidVersion:
            OpalDiagnostics.ErrorCode.invalidVersion
        case OpalCrypto.Key.WIF.Error.invalidCompressionMarker:
            OpalDiagnostics.ErrorCode.invalidCompressionMarker
        case OpalCrypto.Key.WIF.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.Key.WIF.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey
        default:
            nil
        }
    }

    static func extendedKeyErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        if let errorCode = extendedPrivateKeyErrorCode(for: error) {
            return errorCode
        }
        return extendedPublicKeyErrorCode(for: error)
    }

    private static func extendedPrivateKeyErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidBase58:
            OpalDiagnostics.ErrorCode.invalidBase58
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidChecksum:
            OpalDiagnostics.ErrorCode.invalidChecksum
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidVersion:
            OpalDiagnostics.ErrorCode.invalidVersion
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPayloadLength:
            OpalDiagnostics.ErrorCode.invalidPayloadLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidParentFingerprintLength:
            OpalDiagnostics.ErrorCode.invalidParentFingerprintLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidChainCodeLength:
            OpalDiagnostics.ErrorCode.invalidChainCodeLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidSeedLength:
            OpalDiagnostics.ErrorCode.invalidSeedLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidDepthMetadata:
            OpalDiagnostics.ErrorCode.invalidDepthMetadata
        case OpalCrypto.Key.ExtendedPrivate.Error.depthOverflow:
            OpalDiagnostics.ErrorCode.depthOverflow
        case OpalCrypto.Key.ExtendedPrivate.Error.invalidDerivedKey:
            OpalDiagnostics.ErrorCode.invalidDerivedKey
        default:
            nil
        }
    }

    private static func extendedPublicKeyErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.Key.ExtendedPublic.Error.invalidBase58:
            OpalDiagnostics.ErrorCode.invalidBase58
        case OpalCrypto.Key.ExtendedPublic.Error.invalidChecksum:
            OpalDiagnostics.ErrorCode.invalidChecksum
        case OpalCrypto.Key.ExtendedPublic.Error.invalidVersion:
            OpalDiagnostics.ErrorCode.invalidVersion
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPayloadLength:
            OpalDiagnostics.ErrorCode.invalidPayloadLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidParentFingerprintLength:
            OpalDiagnostics.ErrorCode.invalidParentFingerprintLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidChainCodeLength:
            OpalDiagnostics.ErrorCode.invalidChainCodeLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.Key.ExtendedPublic.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey
        case OpalCrypto.Key.ExtendedPublic.Error.invalidDepthMetadata:
            OpalDiagnostics.ErrorCode.invalidDepthMetadata
        case OpalCrypto.Key.ExtendedPublic.Error.hardenedDerivationRequiresPrivateKey:
            OpalDiagnostics.ErrorCode.hardenedDerivationRequiresPrivateKey
        case OpalCrypto.Key.ExtendedPublic.Error.depthOverflow:
            OpalDiagnostics.ErrorCode.depthOverflow
        case OpalCrypto.Key.ExtendedPublic.Error.invalidDerivedKey:
            OpalDiagnostics.ErrorCode.invalidDerivedKey
        default:
            nil
        }
    }
}
