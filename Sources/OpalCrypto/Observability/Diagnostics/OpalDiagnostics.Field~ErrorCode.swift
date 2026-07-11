// OpalDiagnostics.Field~ErrorCode.swift

import OpalDiagnostics

extension OpalDiagnostics.Field {
    static func errorCode(for error: Swift.Error) -> OpalDiagnostics.ErrorCode {
        if let errorCode = mapMetalSchnorrBatchVerificationErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = secp256k1ErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = signatureErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = verificationKeyErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = keyDerivationErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = mnemonicErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = walletImportFormatErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = extendedKeyErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = communicationErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = encodingErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = pedersenErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = blindSignatureErrorCode(for: error) {
            return errorCode
        }
        if let errorCode = internalCodecErrorCode(for: error) {
            return errorCode
        }
        return OpalDiagnostics.ErrorCode(rawValue: String(reflecting: Swift.type(of: error)))
    }
}
