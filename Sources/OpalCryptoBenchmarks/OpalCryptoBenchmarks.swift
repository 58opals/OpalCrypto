// OpalCryptoBenchmarks.swift

import Darwin

@main
enum OpalCryptoBenchmarks {
    @MainActor
    static func main() async {
        do {
            try await run()
        } catch let error as BenchmarkCommandError {
            fputs("Error: \(error.description)\n\n\(BenchmarkOptions.usage)\n", stderr)
            Darwin.exit(EXIT_FAILURE)
        } catch {
            fputs("Error: \(error)\n", stderr)
            Darwin.exit(EXIT_FAILURE)
        }
    }
}
