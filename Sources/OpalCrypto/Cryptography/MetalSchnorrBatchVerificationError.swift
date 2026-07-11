// MetalSchnorrBatchVerificationError.swift

enum MetalSchnorrBatchVerificationError: Swift.Error, Sendable, Equatable {
    case unavailable
    case uncertifiedDevice
    case shaderLibraryUnavailable
    case pipelineCreationFailed
    case bufferAllocationFailed
    case temporaryBufferLimitExceeded
    case commandEncodingFailed
    case commandFailed
    case invalidInput
    case invalidOutput
    case selfTestFailed
}
