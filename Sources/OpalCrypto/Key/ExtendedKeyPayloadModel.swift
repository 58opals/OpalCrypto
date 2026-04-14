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
        parentFingerprint: Data,
        childIndex: UInt32,
        chainCode: Data,
        keyData: Data
    ) throws {
        guard parentFingerprint.count == 4 else {
            throw Error.invalidParentFingerprintLength(actual: parentFingerprint.count)
        }
        try self.init(
            kind: kind,
            depth: depth,
            parentFingerprintUInt32BigEndian: parentFingerprint.uint32BigEndian(at: 0),
            childIndex: childIndex,
            chainCode: chainCode,
            keyData: keyData,
            validationMode: .full
        )
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

    private init(
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
        self.chainCode = chainCode
        self.keyData = keyData
    }

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

    internal init(serialized: String) throws {
        let payload: Data
        do {
            payload = try Base58CheckCodecModel.decode(serialized, minimumPayloadLength: 78)
        } catch let error as Base58CheckCodecModel.Error {
            switch error {
            case .invalidBase58:
                throw Error.invalidBase58
            case .invalidChecksum:
                throw Error.invalidChecksum
            case .invalidPayloadLength(let actual):
                throw Error.invalidPayloadLength(actual: actual)
            }
        }

        guard payload.count == 78 else {
            throw Error.invalidPayloadLength(actual: payload.count)
        }

        let version = payload.uint32BigEndian(at: 0)
        let depth = payload[4]
        let parentFingerprintUInt32BigEndian = payload.uint32BigEndian(at: 5)
        let childIndex = payload.uint32BigEndian(at: 9)
        let chainCode = payload.dataSlice(in: 13..<45)
        let keyPayload = payload.dataSlice(in: 45..<78)

        switch version {
        case Self.privateVersion:
            guard let prefix = keyPayload.first else {
                throw Error.invalidPayloadLength(actual: payload.count)
            }
            guard prefix == 0x00 else {
                throw Error.invalidPrivateKeyPrefix(actual: prefix)
            }
            try self.init(
                kind: .privateKey,
                depth: depth,
                parentFingerprintUInt32BigEndian: parentFingerprintUInt32BigEndian,
                childIndex: childIndex,
                chainCode: chainCode,
                keyData: Data(keyPayload.dropFirst())
            )
        case Self.publicVersion:
            try self.init(
                kind: .publicKey,
                depth: depth,
                parentFingerprintUInt32BigEndian: parentFingerprintUInt32BigEndian,
                childIndex: childIndex,
                chainCode: chainCode,
                keyData: keyPayload
            )
        default:
            throw Error.invalidVersion(actual: version)
        }
    }

    internal func serialize() -> String {
        var payload = Data()
        payload.reserveCapacity(78)
        payload.appendUInt32BigEndian(kind == .privateKey ? Self.privateVersion : Self.publicVersion)
        payload.append(depth)
        payload.appendUInt32BigEndian(parentFingerprintUInt32BigEndian)
        payload.appendUInt32BigEndian(childIndex)
        payload.append(chainCode)
        switch kind {
        case .privateKey:
            payload.append(0x00)
            payload.append(keyData)
        case .publicKey:
            payload.append(keyData)
        }
        return Base58CheckCodecModel.encode(payload: payload)
    }
}
