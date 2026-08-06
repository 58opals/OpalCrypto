// OpalCrypto+SecureRandom.swift

import Foundation

extension OpalCrypto {
    /// Bounded generation of cryptographically secure random bytes.
    public enum SecureRandom {
        /// Creates `count` bytes using the operating system's secure random generator.
        ///
        /// The accepted `1...1024` range is an OpalCrypto allocation-safety boundary, not a protocol constant. Callers with a protocol-shaped value should validate the returned bytes through that value's initializer.
        ///
        /// - Throws: ``Error/invalidByteCount(minimum:maximum:actual:)`` when `count` is outside `1...1024`, or ``Error/generationFailed(status:)`` when the operating system generator fails.
        public static func makeBytes(count: Int) throws -> Data {
            guard minimumByteCount...maximumByteCount ~= count else {
                throw Error.invalidByteCount(
                    minimum: minimumByteCount,
                    maximum: maximumByteCount,
                    actual: count
                )
            }
            do {
                return Data(try SecureRandomByteGenerator.makeBytes(count: count))
            } catch SecureRandomByteGenerator.Error.failed(let status) {
                throw Error.generationFailed(status: status)
            }
        }

        private static let minimumByteCount = 1
        private static let maximumByteCount = 1024
    }
}
