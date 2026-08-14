// RSABSSAKeyModel.swift

import Foundation
import Security
import Synchronization

/// A Sendable key holder that serializes Security.framework calls.
///
/// Apple documents certificate, key, and trust calls as requiring serialized
/// access on macOS. The shared gate also keeps operations on distinct SecKey
/// instances from running concurrently inside this RSABSSA provider.
internal final class RSABSSASecurityKey: @unchecked Sendable {
    private let key: SecKey
    private static let operationGate = Mutex<Void>(())

    internal init(_ key: SecKey) {
        self.key = key
    }

    internal func perform<Result>(
        _ operation: (SecKey) throws -> Result
    ) rethrows -> Result {
        try Self.operationGate.withLock { _ in
            try operation(key)
        }
    }

    internal static func perform<Result>(
        _ operation: () throws -> Result
    ) rethrows -> Result {
        try operationGate.withLock { _ in
            try operation()
        }
    }
}

internal struct RSABSSAVerificationKeyModel: Sendable {
    internal let securityKey: RSABSSASecurityKey
    internal let subjectPublicKeyInfo: Data
    internal let keyIdentifier: Data
    internal let modulus: RSABSSAInteger
    internal let modulusBitCount: Int
    internal let modulusByteCount: Int

    internal init(subjectPublicKeyInfo: Data) throws {
        let material = try RSABSSAKeyEncoding.parseSubjectPublicKeyInfo(
            subjectPublicKeyInfo
        )
        try self.init(
            material: material,
            subjectPublicKeyInfo: subjectPublicKeyInfo,
            expectedModulusBitCount: OpalCrypto.RSABSSA.Variant
                .sha384PSSRandomized.modulusBitCount
        )
    }

    internal init(
        pkcs1Representation: Data,
        expectedModulusBitCount: Int
    ) throws {
        let material = try RSABSSAKeyEncoding.parsePKCS1PublicKey(
            pkcs1Representation
        )
        try self.init(
            material: material,
            subjectPublicKeyInfo: RSABSSAKeyEncoding.makeSubjectPublicKeyInfo(
                pkcs1Representation: pkcs1Representation
            ),
            expectedModulusBitCount: expectedModulusBitCount
        )
    }

    private init(
        material: RSABSSAKeyEncoding.PublicKeyMaterial,
        subjectPublicKeyInfo: Data,
        expectedModulusBitCount: Int
    ) throws {
        let expectedExponent = OpalCrypto.RSABSSA.Variant
            .sha384PSSRandomized.publicExponent
        guard material.publicExponent == expectedExponent else {
            throw OpalCrypto.RSABSSA.Error.invalidPublicExponent(
                expected: expectedExponent,
                actual: material.publicExponent
            )
        }
        guard material.modulusBitCount == expectedModulusBitCount else {
            throw OpalCrypto.RSABSSA.Error.invalidModulusBitCount(
                expected: expectedModulusBitCount,
                actual: material.modulusBitCount
            )
        }

        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits: expectedModulusBitCount
        ]
        let platformKey = try RSABSSASecurityKey.perform {
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateWithData(
                material.pkcs1Representation as CFData,
                attributes as CFDictionary,
                &error
            ) else {
                throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
            }
            return key
        }
        let securityKey = RSABSSASecurityKey(platformKey)
        guard securityKey.perform({ key in
            SecKeyIsAlgorithmSupported(
                key,
                .encrypt,
                .rsaEncryptionRaw
            ) && SecKeyIsAlgorithmSupported(
                key,
                .verify,
                .rsaSignatureMessagePSSSHA384
            )
        }) else {
            throw OpalCrypto.RSABSSA.Error.unsupportedKeyOperation
        }

        self.securityKey = securityKey
        self.subjectPublicKeyInfo = Data(subjectPublicKeyInfo)
        self.keyIdentifier = SecureHashAlgorithm256Model.hash(
            subjectPublicKeyInfo
        )
        self.modulus = material.modulus
        self.modulusBitCount = material.modulusBitCount
        self.modulusByteCount = (material.modulusBitCount + 7) / 8
    }
}

internal struct RSABSSASigningKeyModel: Sendable {
    internal let securityKey: RSABSSASecurityKey
    internal let verificationKey: RSABSSAVerificationKeyModel

    internal static func generate() throws -> Self {
        let variant = OpalCrypto.RSABSSA.Variant.sha384PSSRandomized
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: variant.modulusBitCount,
            kSecAttrIsPermanent: false
        ]
        let privateKey = try RSABSSASecurityKey.perform {
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateRandomKey(
                attributes as CFDictionary,
                &error
            ) else {
                throw OpalCrypto.RSABSSA.Error.keyGenerationFailed
            }
            return key
        }
        do {
            return try Self(privateKey: privateKey)
        } catch {
            throw OpalCrypto.RSABSSA.Error.keyGenerationFailed
        }
    }

    internal init(privateKey: SecKey) throws {
        let securityKey = RSABSSASecurityKey(privateKey)
        guard let publicKey = securityKey.perform({ key -> SecKey? in
            guard let attributes = SecKeyCopyAttributes(key)
                    as? [CFString: Any],
                  attributes[kSecAttrKeyType] as? String
                    == kSecAttrKeyTypeRSA as String,
                  attributes[kSecAttrKeyClass] as? String
                    == kSecAttrKeyClassPrivate as String,
                  SecKeyGetBlockSize(key)
                == OpalCrypto.RSABSSA.Variant.sha384PSSRandomized.modulusByteCount,
                  SecKeyIsAlgorithmSupported(
                    key,
                    .decrypt,
                    .rsaEncryptionRaw
                  ) else {
                return nil
            }
            return SecKeyCopyPublicKey(key)
        }) else {
            throw OpalCrypto.RSABSSA.Error.unsupportedKeyOperation
        }

        guard let representation = RSABSSASecurityKey.perform({ () -> Data? in
            var error: Unmanaged<CFError>?
            return SecKeyCopyExternalRepresentation(
                publicKey,
                &error
            ) as Data?
        }) else {
            throw OpalCrypto.RSABSSA.Error.unsupportedKeyOperation
        }

        self.securityKey = securityKey
        self.verificationKey = try RSABSSAVerificationKeyModel(
            pkcs1Representation: representation,
            expectedModulusBitCount: OpalCrypto.RSABSSA.Variant
                .sha384PSSRandomized.modulusBitCount
        )
    }
}
