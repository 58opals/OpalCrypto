import CryptoKit
import Foundation

/// Current fixture bytes qualified against the immutable sources in the notices.
/// These bindings do not establish the original import or generation history.
enum StandardsFixtureProvenanceData {
    static let nip44MessageKeyCaseSHA256 =
        "b81330ffdd17c83f1fa55efa148f4f2d6a64a3a70c4e7d79bc05bdef68055e93"
    static let nistGCMCaseSHA256 =
        "f38a9559ae5d0e5f3a49a2ca427c4889c0a7e012ae1c773346f642988a64d626"
    static let bchSchnorrRowsSHA256 =
        "3ba975b6e47fbddfeb39fe025da07fb48c3b9ad4e9404aea21625c260fad275c"

    /// Lowercase hexadecimal fields, in the documented order, one LF per field.
    static func digestHexFields(_ fields: [Data]) -> String {
        digest(fields.map { field in
            field.map { String(format: "%02x", $0) }.joined()
        }.joined(separator: "\n") + "\n")
    }

    static func digest(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
