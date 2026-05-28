// PublicKeyParserModel.swift

import Foundation

enum PublicKeyParserModel {
    static func sec1DiagnosticsFormat(for data: Data) -> String {
        switch data.first {
        case 0x02, 0x03:
            return "sec1_compressed"
        case 0x04:
            return "sec1_uncompressed"
        case .some:
            return "sec1_unknown"
        case .none:
            return "sec1_empty"
        }
    }

    static func expectedSec1PublicKeyLength(for data: Data) -> Int {
        guard let prefix = data.first else {
            return 33
        }

        switch prefix {
        case 0x04:
            return 65
        case 0x02, 0x03:
            return 33
        default:
            return data.count > 33 ? 65 : 33
        }
    }

    static func parsePublicKey(_ data: Data) throws -> AffinePointModel {
        guard let prefix = data.first else {
            throw Error.invalidLength(actual: data.count)
        }

        switch prefix {
        case 0x02, 0x03:
            guard data.count == 33 else {
                throw Error.invalidLength(actual: data.count)
            }
            return try parseCompressedPublicKey(data)
        case 0x04:
            guard data.count == 65 else {
                throw Error.invalidLength(actual: data.count)
            }
            return try parseUncompressedPublicKey(data)
        default:
            guard data.count == 33 || data.count == 65 else {
                throw Error.invalidLength(actual: data.count)
            }
            throw Error.invalidPrefix(byte: prefix)
        }
    }

    private static func parseCompressedPublicKey(_ data: Data) throws -> AffinePointModel {
        let prefix = data[data.startIndex]
        let xData = data[data.index(after: data.startIndex)..<data.endIndex]
        let xCoordinate = try FieldElementModel(contiguousBytes32: xData)
        let ySquared = xCoordinate.square().mul(xCoordinate).add(.seven)
        guard var yCoordinate = ySquared.sqrt() else {
            throw Error.invalidPoint
        }

        let isOddYCoordinateExpected = prefix == 0x03
        if yCoordinate.isOdd != isOddYCoordinateExpected {
            yCoordinate = yCoordinate.negate()
        }

        return AffinePointModel(x: xCoordinate, y: yCoordinate)
    }

    private static func parseUncompressedPublicKey(_ data: Data) throws -> AffinePointModel {
        let xStartIndex = data.index(after: data.startIndex)
        let yStartIndex = data.index(xStartIndex, offsetBy: 32)
        let xData = data[xStartIndex..<yStartIndex]
        let yData = data[yStartIndex..<data.endIndex]
        let xCoordinate = try FieldElementModel(contiguousBytes32: xData)
        let yCoordinate = try FieldElementModel(contiguousBytes32: yData)
        let point = AffinePointModel(x: xCoordinate, y: yCoordinate)
        guard point.isOnCurve else {
            throw Error.invalidPoint
        }
        return point
    }
}
