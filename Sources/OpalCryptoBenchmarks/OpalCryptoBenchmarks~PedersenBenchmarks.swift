import Foundation
import OpalCrypto

extension OpalCryptoBenchmarks {
    private static let pedersenBenchmarkInputs:
        Result<[(amount: Int64, nonce: OpalCrypto.Pedersen.Nonce)], Swift.Error> = Result {
            try (1 ... 23).map { ordinal in
                var bytes = Data(repeating: 0, count: 31)
                bytes.append(UInt8(ordinal))
                let amount: Int64 = ordinal == 1 ? -100_000
                    : ordinal == 2 ? 99_800 : 0
                return (amount, try .init(rawRepresentation: bytes))
            }
        }

    private static let pedersenBenchmarkSetup:
        Result<OpalCrypto.Pedersen.Setup, Swift.Error> = Result {
            try .init()
        }

    private enum PedersenBenchmarkError: Swift.Error {
        case invalidCommitmentShape
    }

    static func pedersenBenchmarks() -> [BenchmarkCase] {
        [
            BenchmarkCase(
                name: "Pedersen 23 commitments (reused setup)",
                iterations: 8,
                suites: [.hot],
                operation: .sync { _ in
                    try pedersenBenchmarkCommitments(
                        using: pedersenBenchmarkSetup.get()
                    )
                }
            ),
            BenchmarkCase(
                name: "Pedersen setup and 23 commitments",
                iterations: 8,
                suites: [.hot],
                operation: .sync { _ in
                    try pedersenBenchmarkCommitments(using: .init())
                }
            )
        ]
    }

    private static func pedersenBenchmarkCommitments(
        using setup: OpalCrypto.Pedersen.Setup
    ) throws -> Int {
        var checksum = 0
        for input in try pedersenBenchmarkInputs.get() {
            let commitment = try setup.commit(
                amount: input.amount,
                nonce: input.nonce
            )
            let bytes = commitment.point.uncompressedRepresentation
            guard bytes.count == 65, bytes.first == 0x04,
                  let last = bytes.last else {
                throw PedersenBenchmarkError.invalidCommitmentShape
            }
            checksum &+= Int(last)
        }
        return checksum
    }
}
