// ExtendedKeyPayloadModel.swift

import Foundation

internal struct ExtendedKeyPayloadModel: Sendable, Equatable {
    internal enum Kind: Sendable, Equatable {
        case privateKey
        case publicKey
    }

    internal enum Error: Swift.Error, Equatable {
        case invalidBase58
        case invalidChecksum
        case invalidVersion(actual: UInt32)
        case invalidPayloadLength(actual: Int)
        case invalidParentFingerprintLength(actual: Int)
        case invalidChainCodeLength(actual: Int)
        case invalidDepthMetadata
        case invalidPrivateKeyPrefix(actual: UInt8)
        case invalidPrivateKeyLength(actual: Int)
        case invalidPrivateKey
        case invalidPublicKeyLength(actual: Int)
        case invalidPublicKeyPrefix(actual: UInt8)
        case invalidPublicKey
    }

    internal static let privateVersion: UInt32 = 0x0488_ade4
    internal static let publicVersion: UInt32 = 0x0488_b21e

    internal let kind: Kind
    internal let depth: UInt8
    internal let parentFingerprint: Data
    internal let childIndex: UInt32
    internal let chainCode: Data
    internal let keyData: Data

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
        guard chainCode.count == 32 else {
            throw Error.invalidChainCodeLength(actual: chainCode.count)
        }
        if depth == 0 {
            let zeroFingerprint = Data(repeating: 0x00, count: 4)
            guard parentFingerprint == zeroFingerprint, childIndex == 0 else {
                throw Error.invalidDepthMetadata
            }
        }

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

        self.kind = kind
        self.depth = depth
        self.parentFingerprint = parentFingerprint
        self.childIndex = childIndex
        self.chainCode = chainCode
        self.keyData = keyData
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
        let parentFingerprint = payload.dataSlice(in: 5..<9)
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
                parentFingerprint: parentFingerprint,
                childIndex: childIndex,
                chainCode: chainCode,
                keyData: Data(keyPayload.dropFirst())
            )
        case Self.publicVersion:
            try self.init(
                kind: .publicKey,
                depth: depth,
                parentFingerprint: parentFingerprint,
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
        payload.appendUInt32BigEndian(kind == .privateKey ? Self.privateVersion : Self.publicVersion)
        payload.append(depth)
        payload.append(parentFingerprint)
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
