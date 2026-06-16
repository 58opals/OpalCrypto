// Base32ByteModeRoundTripCase.swift

import Foundation

enum Base32ByteModeRoundTripCase: CaseIterable, CustomStringConvertible, Sendable {
    case singleZeroByte
    case leadingZeroIntegerOne
    case mixedLeadingZeroPayload

    var description: String {
        switch self {
        case .singleZeroByte:
            "singleZeroByte"
        case .leadingZeroIntegerOne:
            "leadingZeroIntegerOne"
        case .mixedLeadingZeroPayload:
            "mixedLeadingZeroPayload"
        }
    }

    var payload: Data {
        switch self {
        case .singleZeroByte:
            Data([0x00])
        case .leadingZeroIntegerOne:
            Data([0x00, 0x00, 0x01])
        case .mixedLeadingZeroPayload:
            Data([0x00, 0x10, 0xFF, 0x00])
        }
    }
}
