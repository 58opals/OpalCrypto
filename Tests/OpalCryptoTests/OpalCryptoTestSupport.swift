import Foundation
import Testing

extension Tag {
    @Tag static var performanceSmoke: Self
}

enum OpalCryptoTestSupport {
    private static let performanceSmokeEnvironmentKey = "OPALCRYPTO_RUN_PERF_TESTS"

    // Keep heavy smoke coverage opt-in so plain `swift test` stays fast.
    static var isPerformanceSmokeEnabled: Bool {
        ProcessInfo.processInfo.environment[performanceSmokeEnvironmentKey] == "1"
    }

    static func makePrivateKeys(count: Int) -> [Data] {
        (1...count).map(makePrivateKey)
    }

    static func makePrivateKey(_ value: Int) -> Data {
        var privateKey = Data(repeating: 0x00, count: 32)
        let resolvedValue = UInt32(value)
        privateKey[28] = UInt8((resolvedValue >> 24) & 0xff)
        privateKey[29] = UInt8((resolvedValue >> 16) & 0xff)
        privateKey[30] = UInt8((resolvedValue >> 8) & 0xff)
        privateKey[31] = UInt8(resolvedValue & 0xff)
        return privateKey
    }
}
