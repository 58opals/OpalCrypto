// OpalCryptoBenchmarks+BenchmarkOperation.swift

extension OpalCryptoBenchmarks {
    enum BenchmarkOperation {
        case sync((BenchmarkContext) throws -> Int)
        case asynchronous(@Sendable (BenchmarkContext) async throws -> Int)
    }
}
