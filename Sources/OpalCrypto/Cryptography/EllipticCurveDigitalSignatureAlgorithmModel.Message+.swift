// EllipticCurveDigitalSignatureAlgorithmModel.Message+.swift

import Foundation
import CryptoKit

extension EllipticCurveDigitalSignatureAlgorithmModel.Message {
    internal static func makeDigest(
        _ digest: CryptoKit.SHA256.Digest,
        hashCount: UInt8 = 1
    ) -> EllipticCurveDigitalSignatureAlgorithmModel.Message {
        .init(representation: .digest(digest: digest, hashRounds: hashCount))
    }

    internal func makeConsensusDigestData32Bytes() throws -> Data {
        let rounds = Int(hashRounds)
        guard rounds > 0 else { throw Error.hashCountMustBeGreaterThanZero }
        let digestData: Data
        switch representation {
        case .payload(let data, _):
            digestData = applyHashRounds(data, rounds: rounds)
        case .digest(let digest, _):
            digestData = applyHashRounds(Data(digest), rounds: rounds - 1)
        }
        guard digestData.count == 32 else {
            throw Error.invalidDigestByteCount(expected: 32, actual: digestData.count)
        }
        return digestData
    }
    
    func makeDataForSignerHashingOnceSecureHashAlgorithm256Internally() throws -> Data {
        let baseData = makeDataForHashingRounds()
        let rounds = max(Int(hashRounds) - 1, 0)
        guard rounds > 0 else { return baseData }
        return applyHashRounds(baseData, rounds: rounds)
    }

    func makeEllipticCurveDigitalSignatureAlgorithmDigestData32Bytes() throws -> Data {
        switch representation {
        case .payload:
            return SecureHashAlgorithm256Model.hash(
                try makeDataForSignerHashingOnceSecureHashAlgorithm256Internally()
            )
        case .digest:
            return try makeConsensusDigestData32Bytes()
        }
    }
}

private extension EllipticCurveDigitalSignatureAlgorithmModel.Message {
    var hashRounds: UInt8 {
        switch representation {
        case .payload(_, let rounds):
            return rounds
        case .digest(_, let rounds):
            return rounds
        }
    }
    
    func makeDataForHashingRounds() -> Data {
        switch representation {
        case .payload(let data, _):
            return data
        case .digest(let digest, _):
            return Data(digest)
        }
    }
    
    func applyHashRounds(_ data: Data, rounds: Int) -> Data {
        var hashedData = data
        for _ in 0..<rounds {
            hashedData = SecureHashAlgorithm256Model.hash(hashedData)
        }
        return hashedData
    }
}
