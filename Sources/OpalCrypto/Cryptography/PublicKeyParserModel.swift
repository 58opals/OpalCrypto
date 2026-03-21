// PublicKeyParserModel.swift

import Foundation

enum PublicKeyParserModel {
    enum Error: Swift.Error, Equatable {
        case invalidLength(actual: Int)
        case invalidPrefix(byte: UInt8)
        case invalidPoint
    }

    static func parsePublicKey(_ data: Data) throws -> AffinePointModel {
        switch data.count {
        case 33:
            return try parseCompressedPublicKey(data)
        case 65:
            return try parseUncompressedPublicKey(data)
        default:
            throw Error.invalidLength(actual: data.count)
        }
    }

    private static func parseCompressedPublicKey(_ data: Data) throws -> AffinePointModel {
        guard let prefix = data.first else {
            throw Error.invalidLength(actual: data.count)
        }
        guard prefix == 0x02 || prefix == 0x03 else {
            throw Error.invalidPrefix(byte: prefix)
        }

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

        let point = AffinePointModel(x: xCoordinate, y: yCoordinate)
        guard point.isOnCurve else {
            throw Error.invalidPoint
        }
        return point
    }

    private static func parseUncompressedPublicKey(_ data: Data) throws -> AffinePointModel {
        guard let prefix = data.first else {
            throw Error.invalidLength(actual: data.count)
        }
        guard prefix == 0x04 else {
            throw Error.invalidPrefix(byte: prefix)
        }

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
