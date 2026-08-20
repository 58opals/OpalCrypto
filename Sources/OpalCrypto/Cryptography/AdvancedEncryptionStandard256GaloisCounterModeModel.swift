// AdvancedEncryptionStandard256GaloisCounterModeModel.swift

import CryptoKit
import Foundation

internal enum AdvancedEncryptionStandard256GaloisCounterModeModel {
    static func seal(
        _ plaintext: Data,
        key: Data,
        authenticatedData: Data,
        nonce: Data
    ) throws -> Data {
        precondition(key.count == OpalCrypto.AuthenticatedEncryption.AES256GCM.keyByteCount)
        precondition(nonce.count == OpalCrypto.AuthenticatedEncryption.AES256GCM.nonceByteCount)

        do {
            let sealedBox = try AES.GCM.seal(
                plaintext,
                using: SymmetricKey(data: key),
                nonce: AES.GCM.Nonce(data: nonce),
                authenticating: authenticatedData
            )
            guard let combinedRepresentation = sealedBox.combined else {
                throw Error.sealingFailed
            }
            return combinedRepresentation
        } catch let error as Error {
            throw error
        } catch {
            throw Error.sealingFailed
        }
    }

    static func validateCombinedRepresentation(_ combinedRepresentation: Data) throws {
        do {
            _ = try AES.GCM.SealedBox(combined: combinedRepresentation)
        } catch {
            throw Error.invalidSealedBox
        }
    }

    static func open(
        _ combinedRepresentation: Data,
        key: Data,
        authenticatedData: Data
    ) throws -> Data {
        precondition(key.count == OpalCrypto.AuthenticatedEncryption.AES256GCM.keyByteCount)

        let sealedBox: AES.GCM.SealedBox
        do {
            sealedBox = try AES.GCM.SealedBox(combined: combinedRepresentation)
        } catch {
            throw Error.invalidSealedBox
        }

        do {
            return try AES.GCM.open(
                sealedBox,
                using: SymmetricKey(data: key),
                authenticating: authenticatedData
            )
        } catch {
            throw Error.authenticationFailed
        }
    }
}
