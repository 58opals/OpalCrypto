// MetalLibraryCompilerToolError.swift

import Foundation

enum MetalLibraryCompilerToolError: Swift.Error, Equatable, LocalizedError {
    case invalidArguments
    case metalToolchainUnavailable
    case compilationFailed

    var errorDescription: String? {
        switch self {
        case .invalidArguments:
            "The Metal library compiler received invalid arguments."
        case .metalToolchainUnavailable:
            "The paired metal and metallib executables are unavailable. Install Xcode's Metal Toolchain component with `xcodebuild -downloadComponent MetalToolchain`, verify `metal` with `/usr/bin/xcrun --toolchain MetalToolchain --find metal`, and confirm that an executable `metallib` is beside the reported path."
        case .compilationFailed:
            "The Metal library compilation command failed."
        }
    }
}
