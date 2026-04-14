// ChallengeHashModel+Error.swift

import Foundation
import CryptoKit

extension ChallengeHashModel {
    enum Error: Swift.Error, Equatable {
        case invalidDigestLength(actual: Int)
    }
}
