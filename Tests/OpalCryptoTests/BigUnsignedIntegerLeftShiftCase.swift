// BigUnsignedIntegerLeftShiftCase.swift

enum BigUnsignedIntegerLeftShiftCase: CaseIterable, CustomStringConvertible, Sendable {
    case identity
    case ordinaryByteShift
    case oversizedThreeByteResultLength
    case oversizedSingleByteResultLength

    var description: String {
        switch self {
        case .identity:
            "identity"
        case .ordinaryByteShift:
            "ordinaryByteShift"
        case .oversizedThreeByteResultLength:
            "oversizedThreeByteResultLength"
        case .oversizedSingleByteResultLength:
            "oversizedSingleByteResultLength"
        }
    }

    var inputBytes: [UInt8] {
        switch self {
        case .identity,
             .ordinaryByteShift,
             .oversizedThreeByteResultLength:
            [0x01, 0x02, 0x03]
        case .oversizedSingleByteResultLength:
            [0x01]
        }
    }

    var shiftByteCount: UInt {
        switch self {
        case .identity:
            0
        case .ordinaryByteShift:
            2
        case .oversizedThreeByteResultLength:
            UInt(Int.max - 2)
        case .oversizedSingleByteResultLength:
            UInt(Int.max)
        }
    }

    var expectedBytes: [UInt8]? {
        switch self {
        case .identity:
            [0x01, 0x02, 0x03]
        case .ordinaryByteShift:
            [0x01, 0x02, 0x03, 0x00, 0x00]
        case .oversizedThreeByteResultLength,
             .oversizedSingleByteResultLength:
            nil
        }
    }
}
