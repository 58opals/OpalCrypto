// ExtendedKeyDerivationModel~DigestInput.swift

import Foundation

extension ExtendedKeyDerivationModel {
    static func makePrivateChildDigestInput(
        parentCompressedPublicKeyData: Data,
        parentPrivateKeyData32Bytes: Data,
        index: UInt32
    ) -> Data {
        precondition(parentCompressedPublicKeyData.count == 33)
        precondition(parentPrivateKeyData32Bytes.count == 32)

        if isHardened(index) {
            var digestInput = Data(count: 37)
            digestInput.withUnsafeMutableBytes { rawBuffer in
                // SAFETY: Data(count: 37) guarantees nonempty, contiguous,
                // writable storage for this closure. UInt8 requires byte
                // alignment, and the 1 + 32 + 4 byte writes exactly fill it.
                let destination = rawBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self)
                destination[0] = 0x00
                parentPrivateKeyData32Bytes.copyBytes(
                    to: destination.advanced(by: 1),
                    count: 32
                )
                writeUInt32BigEndian(index, to: destination.advanced(by: 33))
            }
            return digestInput
        }

        return makePublicChildDigestInput(
            parentCompressedPublicKeyData: parentCompressedPublicKeyData,
            index: index
        )
    }

    static func makePublicChildDigestInput(
        parentCompressedPublicKeyData: Data,
        index: UInt32
    ) -> Data {
        precondition(parentCompressedPublicKeyData.count == 33)

        var digestInput = Data(count: 37)
        digestInput.withUnsafeMutableBytes { rawBuffer in
            // SAFETY: Data(count: 37) guarantees nonempty, contiguous, writable
            // storage for this closure. UInt8 requires byte alignment, and the
            // 33-byte key plus 4-byte index exactly fill the allocation.
            let destination = rawBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self)
            parentCompressedPublicKeyData.copyBytes(to: destination, count: 33)
            writeUInt32BigEndian(index, to: destination.advanced(by: 33))
        }
        return digestInput
    }

    static func writeUInt32BigEndian(
        _ value: UInt32,
        to destination: UnsafeMutablePointer<UInt8>
    ) {
        destination[0] = UInt8((value >> 24) & 0xff)
        destination[1] = UInt8((value >> 16) & 0xff)
        destination[2] = UInt8((value >> 8) & 0xff)
        destination[3] = UInt8(value & 0xff)
    }
}
