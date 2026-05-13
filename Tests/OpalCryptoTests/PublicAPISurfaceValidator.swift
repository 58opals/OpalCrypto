// PublicAPISurfaceValidator.swift

import Foundation
import Testing

@Suite("Public API surface validation")
struct PublicAPISurfaceValidator {
    @Test("Public facade does not expose raw Data for constrained cryptographic values")
    func validatePublicFacadeDoesNotExposeRawDataForConstrainedCryptographicValues() throws {
        let publicAPIDirectory = try packageRoot()
            .appendingPathComponent("Sources/OpalCrypto/PublicAPI", isDirectory: true)
        let fileURLs = try FileManager.default.contentsOfDirectory(
            at: publicAPIDirectory,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "swift" }

        let forbiddenPattern =
            #"public\s+(?:static\s+)?(?:func|init)\b[^{]*\b(?:privateKey|publicKey|digest|signature|nonce|symmetricKey|ciphertext)\s*:\s*Data\b"#
        let expression = try NSRegularExpression(
            pattern: forbiddenPattern,
            options: [.dotMatchesLineSeparators]
        )
        var violations: [String] = []

        for fileURL in fileURLs {
            let source = try String(contentsOf: fileURL, encoding: .utf8)
            let range = NSRange(source.startIndex..<source.endIndex, in: source)
            if expression.firstMatch(in: source, range: range) != nil {
                violations.append(fileURL.lastPathComponent)
            }
        }

        #expect(violations.isEmpty, "Raw constrained Data public API remains in: \(violations.sorted())")
    }

    private func packageRoot() throws -> URL {
        var directory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)

        while directory.path != "/" {
            let candidate = directory.appendingPathComponent("Package.swift")
            if FileManager.default.fileExists(atPath: candidate.path) {
                return directory
            }
            directory.deleteLastPathComponent()
        }

        throw PackageRootError.notFound
    }
}
