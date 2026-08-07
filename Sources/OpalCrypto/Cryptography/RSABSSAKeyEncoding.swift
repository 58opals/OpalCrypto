// RSABSSAKeyEncoding.swift

import Foundation

internal enum RSABSSAKeyEncoding {
    internal struct PublicKeyMaterial: Sendable {
        internal let pkcs1Representation: Data
        internal let modulus: RSABSSAInteger
        internal let modulusBitCount: Int
        internal let publicExponent: Int
    }

    internal static func parseSubjectPublicKeyInfo(
        _ representation: Data
    ) throws -> PublicKeyMaterial {
        var documentReader = Reader(bytes: [UInt8](representation))
        let document = try documentReader.read(tag: sequenceTag)
        try documentReader.requireEnd()

        var contentReader = Reader(bytes: document.content)
        let algorithm = try contentReader.read(tag: sequenceTag)
        guard algorithm.encoded == [UInt8](rsaPSSAlgorithmIdentifier) else {
            throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
        }

        let subjectPublicKey = try contentReader.read(tag: bitStringTag)
        try contentReader.requireEnd()
        guard subjectPublicKey.content.first == 0 else {
            throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
        }

        let pkcs1Representation = Data(subjectPublicKey.content.dropFirst())
        let material = try parsePKCS1PublicKey(pkcs1Representation)
        guard makeSubjectPublicKeyInfo(
            pkcs1Representation: material.pkcs1Representation
        ) == representation else {
            throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
        }
        return material
    }

    internal static func parsePKCS1PublicKey(
        _ representation: Data
    ) throws -> PublicKeyMaterial {
        var documentReader = Reader(bytes: [UInt8](representation))
        let document = try documentReader.read(tag: sequenceTag)
        try documentReader.requireEnd()

        var contentReader = Reader(bytes: document.content)
        let modulusElement = try contentReader.read(tag: integerTag)
        let exponentElement = try contentReader.read(tag: integerTag)
        try contentReader.requireEnd()

        let modulusBytes = try positiveIntegerBytes(from: modulusElement.content)
        let exponentBytes = try positiveIntegerBytes(from: exponentElement.content)
        guard exponentBytes.count <= MemoryLayout<Int>.size else {
            throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
        }

        var exponent = 0
        for byte in exponentBytes {
            let multiplied = exponent.multipliedReportingOverflow(by: 256)
            let added = multiplied.partialValue.addingReportingOverflow(Int(byte))
            guard !multiplied.overflow, !added.overflow else {
                throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
            }
            exponent = added.partialValue
        }

        let modulus = RSABSSAInteger(
            bigEndianRepresentation: Data(modulusBytes)
        )
        guard !modulus.isZero else {
            throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
        }
        return PublicKeyMaterial(
            pkcs1Representation: representation,
            modulus: modulus,
            modulusBitCount: modulus.bitCount,
            publicExponent: exponent
        )
    }

    internal static func makeSubjectPublicKeyInfo(
        pkcs1Representation: Data
    ) -> Data {
        var bitStringContent = Data([0])
        bitStringContent.append(pkcs1Representation)

        var content = rsaPSSAlgorithmIdentifier
        content.append(encode(tag: bitStringTag, content: bitStringContent))
        return encode(tag: sequenceTag, content: content)
    }

    internal static func makePKCS1PublicKey(
        modulus: Data,
        publicExponent: Int
    ) -> Data {
        precondition(publicExponent > 0)
        var exponent = publicExponent
        var exponentBytes: [UInt8] = []
        while exponent > 0 {
            exponentBytes.append(UInt8(truncatingIfNeeded: exponent))
            exponent >>= 8
        }

        var content = encodePositiveInteger(modulus)
        content.append(
            encodePositiveInteger(Data(exponentBytes.reversed()))
        )
        return encode(tag: sequenceTag, content: content)
    }

    private static let sequenceTag: UInt8 = 0x30
    private static let integerTag: UInt8 = 0x02
    private static let bitStringTag: UInt8 = 0x03

    /// RFC 9578 Section 6.5's explicit SHA-384, MGF1-SHA384, and saltLength 48
    /// AlgorithmIdentifier. The default trailer field is intentionally absent.
    private static let rsaPSSAlgorithmIdentifier = Data([
        0x30, 0x3d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
        0x30, 0x30,
        0xa0, 0x0d,
        0x30, 0x0b,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0xa1, 0x1a,
        0x30, 0x18,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
        0x30, 0x0b,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0xa2, 0x03,
        0x02, 0x01, 0x30
    ])

    private static func positiveIntegerBytes(
        from content: [UInt8]
    ) throws -> [UInt8] {
        guard let first = content.first, first & 0x80 == 0 else {
            throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
        }
        if content.count > 1, first == 0 {
            guard content[1] & 0x80 != 0 else {
                throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
            }
            return Array(content.dropFirst())
        }
        return content
    }

    private static func encodePositiveInteger(_ value: Data) -> Data {
        var normalized = Array(value.drop { $0 == 0 })
        if normalized.isEmpty {
            normalized = [0]
        } else if normalized[0] & 0x80 != 0 {
            normalized.insert(0, at: 0)
        }
        return encode(tag: integerTag, content: Data(normalized))
    }

    private static func encode(tag: UInt8, content: Data) -> Data {
        var result = Data([tag])
        result.append(contentsOf: encodeLength(content.count))
        result.append(content)
        return result
    }

    private static func encodeLength(_ length: Int) -> [UInt8] {
        precondition(length >= 0)
        guard length >= 128 else { return [UInt8(length)] }

        var remaining = length
        var bytes: [UInt8] = []
        while remaining > 0 {
            bytes.append(UInt8(truncatingIfNeeded: remaining))
            remaining >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes.reversed()
    }

    private struct Element {
        let content: [UInt8]
        let encoded: [UInt8]
    }

    private struct Reader {
        let bytes: [UInt8]
        var offset = 0

        mutating func read(tag expectedTag: UInt8) throws -> Element {
            let start = offset
            guard offset < bytes.count, bytes[offset] == expectedTag else {
                throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
            }
            offset += 1
            let length = try readLength()
            guard length <= bytes.count - offset else {
                throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
            }
            let end = offset + length
            let content = Array(bytes[offset ..< end])
            offset = end
            return Element(
                content: content,
                encoded: Array(bytes[start ..< end])
            )
        }

        mutating func requireEnd() throws {
            guard offset == bytes.count else {
                throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
            }
        }

        private mutating func readLength() throws -> Int {
            guard offset < bytes.count else {
                throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
            }
            let first = bytes[offset]
            offset += 1
            guard first & 0x80 != 0 else { return Int(first) }

            let byteCount = Int(first & 0x7f)
            guard byteCount > 0,
                  byteCount <= MemoryLayout<Int>.size,
                  byteCount <= bytes.count - offset,
                  bytes[offset] != 0 else {
                throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
            }

            var length = 0
            for _ in 0 ..< byteCount {
                let multiplied = length.multipliedReportingOverflow(by: 256)
                let added = multiplied.partialValue.addingReportingOverflow(
                    Int(bytes[offset])
                )
                guard !multiplied.overflow, !added.overflow else {
                    throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
                }
                length = added.partialValue
                offset += 1
            }
            guard length >= 128 else {
                throw OpalCrypto.RSABSSA.Error.invalidSubjectPublicKeyInfo
            }
            return length
        }
    }
}
