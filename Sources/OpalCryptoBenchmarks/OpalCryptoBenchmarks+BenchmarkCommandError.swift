// OpalCryptoBenchmarks+BenchmarkCommandError.swift

extension OpalCryptoBenchmarks {
    enum BenchmarkCommandError: Error, CustomStringConvertible {
        case invalidPositiveInteger(option: String, value: String)
        case metalValidationConflict([String])
        case missingValue(String)
        case noMatchingBenchmarks
        case unknownArgument(String)
        case unknownSuite(String)

        var description: String {
            switch self {
            case let .invalidPositiveInteger(option, value):
                "Invalid value \(value) for \(option). Expected a positive integer."
            case let .metalValidationConflict(options):
                "--validate-metal must be used alone; remove \(options.joined(separator: ", "))."
            case let .missingValue(option):
                "Missing value for \(option)."
            case .noMatchingBenchmarks:
                "No benchmarks matched the selected suite and filter."
            case let .unknownArgument(argument):
                "Unknown argument \(argument)."
            case let .unknownSuite(suite):
                "Unknown suite \(suite). Expected one of \(BenchmarkSuite.allowedValuesText)."
            }
        }
    }
}
