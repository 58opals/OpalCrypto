// PasswordBasedKeyDerivationInvalidParameterCase.swift

import OpalCrypto

enum PasswordBasedKeyDerivationInvalidParameterCase: CaseIterable, CustomStringConvertible, Sendable {
    case zeroIterationCount
    case negativeIterationCount
    case zeroDerivedKeyLength
    case negativeDerivedKeyLength

    var description: String {
        switch self {
        case .zeroIterationCount:
            "zeroIterationCount"
        case .negativeIterationCount:
            "negativeIterationCount"
        case .zeroDerivedKeyLength:
            "zeroDerivedKeyLength"
        case .negativeDerivedKeyLength:
            "negativeDerivedKeyLength"
        }
    }

    var iterationCount: Int {
        switch self {
        case .zeroIterationCount:
            0
        case .negativeIterationCount:
            -1
        case .zeroDerivedKeyLength,
             .negativeDerivedKeyLength:
            16
        }
    }

    var derivedKeyLength: Int? {
        switch self {
        case .zeroIterationCount,
             .negativeIterationCount:
            32
        case .zeroDerivedKeyLength:
            0
        case .negativeDerivedKeyLength:
            -1
        }
    }

    var expectedError: OpalCrypto.KeyDerivation.Error {
        switch self {
        case .zeroIterationCount:
            .invalidIterationCount(actual: 0)
        case .negativeIterationCount:
            .invalidIterationCount(actual: -1)
        case .zeroDerivedKeyLength:
            .invalidDerivedKeyLength(actual: 0)
        case .negativeDerivedKeyLength:
            .invalidDerivedKeyLength(actual: -1)
        }
    }
}
