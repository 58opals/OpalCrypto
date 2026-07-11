// OpalCryptoBenchmarks+BenchmarkReporter.swift

import Foundation

extension OpalCryptoBenchmarks {
    final class BenchmarkReporter {
        private let fileHandle: FileHandle?

        init(outputPath: String?) throws {
            guard let outputPath else {
                fileHandle = nil
                return
            }

            let currentDirectory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            let outputURL = URL(fileURLWithPath: outputPath, relativeTo: currentDirectory)
                .standardizedFileURL
            let directoryURL = outputURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true,
                attributes: nil
            )
            _ = FileManager.default.createFile(atPath: outputURL.path, contents: nil)
            fileHandle = try FileHandle(forWritingTo: outputURL)
        }

        deinit {
            try? fileHandle?.close()
        }

        func recordRun(_ metadata: BenchmarkRunMetadata) throws {
            try writeJSONLine(metadata.jsonObject)
        }

        func recordBenchmark(_ result: BenchmarkResult) throws {
            try writeJSONLine(result.jsonObject)
        }

        func recordSummary(
            executedBenchmarkCount: Int,
            checksum: Int
        ) throws {
            try writeJSONLine(
                [
                    "type": "benchmark_summary",
                    "executed_benchmark_count": executedBenchmarkCount,
                    "checksum": checksum
                ]
            )
        }

        private func writeJSONLine(_ object: [String: Any]) throws {
            let data = try JSONSerialization.data(
                withJSONObject: object,
                options: [.sortedKeys]
            )
            guard let line = String(data: data, encoding: .utf8) else {
                return
            }
            print(line)
            guard let fileHandle else {
                return
            }
            fileHandle.write(Data((line + "\n").utf8))
        }
    }
}
