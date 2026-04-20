// ExtendedKeyPayloadModel~TrustedConstruction.swift

import Foundation

extension ExtendedKeyPayloadModel {
    internal static func makeTrustedDerivedPrivateKey(
        depth: UInt8,
        parentFingerprintUInt32BigEndian: UInt32,
        childIndex: UInt32,
        chainCode: Data,
        privateKeyData32Bytes: Data
    ) -> ExtendedKeyPayloadModel {
        try! ExtendedKeyPayloadModel(
            kind: .privateKey,
            depth: depth,
            parentFingerprintUInt32BigEndian: parentFingerprintUInt32BigEndian,
            childIndex: childIndex,
            chainCode: chainCode,
            keyData: privateKeyData32Bytes,
            validationMode: .trusted
        )
    }

    internal static func makeTrustedDerivedPublicKey(
        depth: UInt8,
        parentFingerprintUInt32BigEndian: UInt32,
        childIndex: UInt32,
        chainCode: Data,
        publicKeyData33Bytes: Data
    ) -> ExtendedKeyPayloadModel {
        try! ExtendedKeyPayloadModel(
            kind: .publicKey,
            depth: depth,
            parentFingerprintUInt32BigEndian: parentFingerprintUInt32BigEndian,
            childIndex: childIndex,
            chainCode: chainCode,
            keyData: publicKeyData33Bytes,
            validationMode: .trusted
        )
    }
}
