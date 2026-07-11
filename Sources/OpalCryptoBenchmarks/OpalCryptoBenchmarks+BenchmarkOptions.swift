// OpalCryptoBenchmarks+BenchmarkOptions.swift

extension OpalCryptoBenchmarks {
    struct BenchmarkOptions {
        static let defaultWarmupIterations = 1
        static let defaultMeasurementSampleCount = 3

        let suite: BenchmarkSuite
        let filter: String?
        let outputPath: String?
        let warmupIterations: Int
        let measurementSampleCount: Int
        let shouldList: Bool
        let shouldShowHelp: Bool
        let shouldValidateMetal: Bool

        static let usage = """
            Usage: OpalCryptoBenchmarks [--suite smoke|hot|metal|full] [--filter text] [--output path] [--warmups N] [--samples N] [--list] [--help]
                   OpalCryptoBenchmarks --validate-metal

            Options:
              --suite smoke|hot|metal|full  Select benchmark suite. Defaults to full.
              --filter text                 Run benchmark names containing text, case-insensitive.
              --output path                 Write JSONL records to path, creating parent directories.
              --warmups N                   Set positive warmup count. Defaults to 1.
              --samples N                   Set positive measurement sample count. Defaults to 3.
              --list                        Print selected benchmark names without running them.
              --validate-metal              Run Metal correctness validation. Must be used alone.
              --help                        Print this help text.
            """

        static func parse(_ arguments: [String]) throws -> BenchmarkOptions {
            let normalizedArguments = arguments.first == "--"
                ? Array(arguments.dropFirst())
                : arguments
            if let validationOptionIndex = normalizedArguments.firstIndex(
                of: "--validate-metal"
            ) {
                var conflictingArguments = normalizedArguments
                conflictingArguments.remove(at: validationOptionIndex)
                guard conflictingArguments.isEmpty else {
                    throw BenchmarkCommandError.metalValidationConflict(conflictingArguments)
                }
            }

            var suite: BenchmarkSuite = .full
            var filter: String?
            var outputPath: String?
            var warmupIterations = defaultWarmupIterations
            var measurementSampleCount = defaultMeasurementSampleCount
            var shouldList = false
            var shouldShowHelp = false
            var shouldValidateMetal = false

            var index = 0
            while index < normalizedArguments.count {
                let argument = normalizedArguments[index]
                switch argument {
                case "--suite":
                    let value = try value(
                        after: "--suite",
                        at: index,
                        in: normalizedArguments
                    )
                    index += 1
                    guard let parsedSuite = BenchmarkSuite(rawValue: value) else {
                        throw BenchmarkCommandError.unknownSuite(value)
                    }
                    suite = parsedSuite
                case "--filter":
                    filter = try value(after: "--filter", at: index, in: normalizedArguments)
                    index += 1
                case "--output":
                    outputPath = try value(after: "--output", at: index, in: normalizedArguments)
                    index += 1
                case "--warmups":
                    let value = try value(after: "--warmups", at: index, in: normalizedArguments)
                    warmupIterations = try positiveInteger(value, for: argument)
                    index += 1
                case "--samples":
                    let value = try value(after: "--samples", at: index, in: normalizedArguments)
                    measurementSampleCount = try positiveInteger(value, for: argument)
                    index += 1
                case "--list":
                    shouldList = true
                case "--validate-metal":
                    shouldValidateMetal = true
                case "--help", "-h":
                    shouldShowHelp = true
                default:
                    throw BenchmarkCommandError.unknownArgument(argument)
                }
                index += 1
            }

            return BenchmarkOptions(
                suite: suite,
                filter: filter,
                outputPath: outputPath,
                warmupIterations: warmupIterations,
                measurementSampleCount: measurementSampleCount,
                shouldList: shouldList,
                shouldShowHelp: shouldShowHelp,
                shouldValidateMetal: shouldValidateMetal
            )
        }

        func filterMatches(name: String) -> Bool {
            guard let filter else {
                return true
            }
            return name.localizedCaseInsensitiveContains(filter)
        }

        private static func value(
            after option: String,
            at index: Int,
            in arguments: [String]
        ) throws -> String {
            let valueIndex = index + 1
            guard valueIndex < arguments.count,
                  !arguments[valueIndex].hasPrefix("--") else {
                throw BenchmarkCommandError.missingValue(option)
            }
            return arguments[valueIndex]
        }

        private static func positiveInteger(
            _ value: String,
            for option: String
        ) throws -> Int {
            guard let integer = Int(value), integer > 0 else {
                throw BenchmarkCommandError.invalidPositiveInteger(option: option, value: value)
            }
            return integer
        }
    }
}
