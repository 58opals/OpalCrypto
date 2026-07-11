// OpalCryptoBenchmarks+BenchmarkSuite.swift

extension OpalCryptoBenchmarks {
    enum BenchmarkSuite: String, CaseIterable {
        case smoke
        case hot
        case metal
        case full

        static var allowedValuesText: String {
            allCases.map(\.rawValue).joined(separator: "|")
        }
    }
}
