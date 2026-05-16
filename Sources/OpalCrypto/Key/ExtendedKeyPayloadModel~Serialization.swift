// ExtendedKeyPayloadModel~Serialization.swift

import Foundation

extension ExtendedKeyPayloadModel {
    internal init(serialized: String) throws {
        let payload: Data
        do {
            payload = try Base58CheckCodec.decode(serialized, minimumPayloadLength: 78)
        } catch let error as Base58CheckCodec.Error {
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
        return Base58CheckCodec.encode(payload: payload)
    }
}
