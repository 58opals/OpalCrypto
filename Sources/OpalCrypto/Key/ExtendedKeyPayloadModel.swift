// ExtendedKeyPayloadModel.swift

import Foundation

internal struct ExtendedKeyPayloadModel: Sendable, Equatable {
    internal static let privateVersion: UInt32 = 0x0488_ade4
    internal static let publicVersion: UInt32 = 0x0488_b21e

    internal let kind: Kind
    internal let depth: UInt8
    internal let parentFingerprintUInt32BigEndian: UInt32
    internal let childIndex: UInt32
    internal let chainCode: Data
    internal let keyData: Data

    internal var parentFingerprint: Data {
        Data(bigEndianUInt32: parentFingerprintUInt32BigEndian)
    }

    internal init(
        kind: Kind,
        depth: UInt8,
        parentFingerprintUInt32BigEndian: UInt32,
        childIndex: UInt32,
        chainCode: Data,
        keyData: Data
    ) throws {
        try self.init(
            kind: kind,
            depth: depth,
            parentFingerprintUInt32BigEndian: parentFingerprintUInt32BigEndian,
            childIndex: childIndex,
            chainCode: chainCode,
            keyData: keyData,
            validationMode: .full
        )
    }

    init(
        kind: Kind,
        depth: UInt8,
        parentFingerprintUInt32BigEndian: UInt32,
        childIndex: UInt32,
        chainCode: Data,
        keyData: Data,
        validationMode: ValidationMode
    ) throws {
        guard chainCode.count == 32 else {
            throw Error.invalidChainCodeLength(actual: chainCode.count)
        }
        if depth == 0 {
            guard parentFingerprintUInt32BigEndian == 0, childIndex == 0 else {
                throw Error.invalidDepthMetadata
            }
        }

        switch validationMode {
        case .full:
            switch kind {
            case .privateKey:
                guard keyData.count == 32 else {
                    throw Error.invalidPrivateKeyLength(actual: keyData.count)
                }
                guard StandardsForEfficientCryptography256k1CurveModel.Operation
                    .isPrivateKeyData32BytesValid(keyData) else {
                    throw Error.invalidPrivateKey
                }
            case .publicKey:
                guard keyData.count == 33 else {
                    throw Error.invalidPublicKeyLength(actual: keyData.count)
                }
                guard let prefix = keyData.first else {
                    throw Error.invalidPublicKeyLength(actual: keyData.count)
                }
                guard prefix == 0x02 || prefix == 0x03 else {
                    throw Error.invalidPublicKeyPrefix(actual: prefix)
                }
                do {
                    _ = try StandardsForEfficientCryptography256k1CurveModel.Operation
                        .parsePublicKeyAffine(keyData)
                } catch {
                    throw Error.invalidPublicKey
                }
            }
        case .trusted:
            switch kind {
            case .privateKey:
                precondition(keyData.count == 32)
            case .publicKey:
                precondition(keyData.count == 33)
                precondition(keyData.first == 0x02 || keyData.first == 0x03)
            }
        }

        self.kind = kind
        self.depth = depth
        self.parentFingerprintUInt32BigEndian = parentFingerprintUInt32BigEndian
        self.childIndex = childIndex
        self.chainCode = Data(chainCode)
        self.keyData = Data(keyData)
    }
}
