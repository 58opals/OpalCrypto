// OpalDiagnostics.Field~CommunicationErrorCode.swift

import OpalDiagnostics

extension OpalDiagnostics.Field {
    static func communicationErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.Communication.Error.messageTooLong:
            OpalDiagnostics.ErrorCode.messageTooLong
        case OpalCrypto.Communication.Error.invalidPublicKeyLength:
            OpalDiagnostics.ErrorCode.invalidPublicKeyLength
        case OpalCrypto.Communication.Error.invalidPublicKeyPrefix:
            OpalDiagnostics.ErrorCode.invalidPublicKeyPrefix
        case OpalCrypto.Communication.Error.invalidPublicKey:
            OpalDiagnostics.ErrorCode.invalidPublicKey
        case OpalCrypto.Communication.Error.invalidPrivateKeyLength:
            OpalDiagnostics.ErrorCode.invalidPrivateKeyLength
        case OpalCrypto.Communication.Error.invalidPrivateKey:
            OpalDiagnostics.ErrorCode.invalidPrivateKey
        case OpalCrypto.Communication.Error.invalidSymmetricKeyLength:
            OpalDiagnostics.ErrorCode.invalidSymmetricKeyLength
        case OpalCrypto.Communication.Error.invalidPaddedPlaintextLength:
            OpalDiagnostics.ErrorCode.invalidPaddedPlaintextLength
        case OpalCrypto.Communication.Error.paddedPlaintextLengthMustBeMultipleOf16:
            OpalDiagnostics.ErrorCode.paddedPlaintextLengthMustBeMultipleOf16
        case OpalCrypto.Communication.Error.ciphertextByteCountExceedsMaximum:
            OpalDiagnostics.ErrorCode.ciphertextByteCountExceedsMaximum
        case OpalCrypto.Communication.Error.ciphertextByteCountOverflow:
            OpalDiagnostics.ErrorCode.ciphertextByteCountOverflow
        case OpalCrypto.Communication.Error.invalidCiphertext:
            OpalDiagnostics.ErrorCode.invalidCiphertext
        case OpalCrypto.Communication.Error.cryptographyFailure:
            OpalDiagnostics.ErrorCode.cryptographyFailure
        default:
            nil
        }
    }

    static func encodingErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case OpalCrypto.Encoding.Base58DecodingError.invalidText:
            OpalDiagnostics.ErrorCode.invalidBase58
        case OpalCrypto.Encoding.Base58DecodingError.invalidMaximumDecodedByteCount:
            OpalDiagnostics.ErrorCode.invalidMaximumDecodedByteCount
        case OpalCrypto.Encoding.Base58DecodingError.decodedDataExceedsMaximumByteCount:
            OpalDiagnostics.ErrorCode.decodedDataExceedsMaximumByteCount
        case OpalCrypto.Encoding.Error.invalidFiveBitValue:
            OpalDiagnostics.ErrorCode.invalidFiveBitValue
        case OpalCrypto.Encoding.Error.invalidCharacterFound:
            OpalDiagnostics.ErrorCode.invalidCharacterFound
        case OpalCrypto.Encoding.Error.invalidMaximumDecodedByteCount:
            OpalDiagnostics.ErrorCode.invalidMaximumDecodedByteCount
        case OpalCrypto.Encoding.Error.decodedDataExceedsMaximumByteCount:
            OpalDiagnostics.ErrorCode.decodedDataExceedsMaximumByteCount
        default:
            nil
        }
    }

    static func internalCodecErrorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode? {
        switch error {
        case Base32EncodingCodec.Error.invalidFiveBitValue:
            OpalDiagnostics.ErrorCode.invalidFiveBitValue
        case Base32EncodingCodec.Error.invalidCharacterFound:
            OpalDiagnostics.ErrorCode.invalidCharacterFound
        case Base32EncodingCodec.Error.invalidMaximumDecodedByteCount:
            OpalDiagnostics.ErrorCode.invalidMaximumDecodedByteCount
        case Base32EncodingCodec.Error.decodedDataExceedsMaximumByteCount:
            OpalDiagnostics.ErrorCode.decodedDataExceedsMaximumByteCount
        case Base58EncodingCodec.Error.invalidCharacterFound:
            OpalDiagnostics.ErrorCode.invalidBase58
        case Base58EncodingCodec.Error.invalidMaximumDecodedByteCount:
            OpalDiagnostics.ErrorCode.invalidMaximumDecodedByteCount
        case Base58EncodingCodec.Error.decodedDataExceedsMaximumByteCount:
            OpalDiagnostics.ErrorCode.decodedDataExceedsMaximumByteCount
        case Base58CheckCodec.Error.invalidBase58:
            OpalDiagnostics.ErrorCode.invalidBase58
        case Base58CheckCodec.Error.invalidChecksum:
            OpalDiagnostics.ErrorCode.invalidChecksum
        case Base58CheckCodec.Error.invalidPayloadLength:
            OpalDiagnostics.ErrorCode.invalidPayloadLength
        case Base58CheckCodec.Error.payloadLengthExceedsMaximum:
            OpalDiagnostics.ErrorCode.payloadLengthExceedsMaximum
        case PasswordBasedKeyDerivationFunction2Model.Error.invalidIterationCount:
            OpalDiagnostics.ErrorCode.invalidIterationCount
        case PasswordBasedKeyDerivationFunction2Model.Error.emptySalt:
            OpalDiagnostics.ErrorCode.emptySalt
        case PasswordBasedKeyDerivationFunction2Model.Error.invalidDerivedKeyLength:
            OpalDiagnostics.ErrorCode.invalidDerivedKeyLength
        case PasswordBasedKeyDerivationFunction2Model.Error.keyLengthExceedsLimit:
            OpalDiagnostics.ErrorCode.derivedKeyLengthExceedsLimit
        case PasswordBasedKeyDerivationFunction2Model.Error.workBudgetExceeded:
            OpalDiagnostics.ErrorCode.workBudgetExceeded
        case PasswordBasedKeyDerivationFunction2Model.Error.workUnitCountOverflow:
            OpalDiagnostics.ErrorCode.workUnitCountOverflow
        default:
            nil
        }
    }
}
