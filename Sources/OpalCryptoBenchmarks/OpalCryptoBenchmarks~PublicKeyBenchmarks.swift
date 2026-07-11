// OpalCryptoBenchmarks~PublicKeyBenchmarks.swift

extension OpalCryptoBenchmarks {
    static func publicKeyBenchmarks() -> [BenchmarkCase] {
        publicKeyDerivationBenchmarkCases() + publicKeyPrimitiveBenchmarkCases()
    }
}
