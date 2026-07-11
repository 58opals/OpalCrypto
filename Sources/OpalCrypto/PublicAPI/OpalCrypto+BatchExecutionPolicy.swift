// OpalCrypto+BatchExecutionPolicy.swift

extension OpalCrypto {
    /// Selects how a supported batch operation is executed.
    ///
    /// Use ``automatic`` for normal operation. Explicit policies are useful for
    /// controlled workloads and performance measurement.
    public struct BatchExecutionPolicy: Sendable, Equatable {
        /// Selects the qualified backend for the current workload and environment.
        public static let automatic = Self(executionMode: .automatic)

        /// Requires the optimized Swift CPU implementation.
        public static let cpu = Self(executionMode: .cpu)

        /// Requires qualified Metal execution without falling back to the CPU.
        public static let metal = Self(executionMode: .metal)

        internal let executionMode: BatchExecutionMode

        private init(executionMode: BatchExecutionMode) {
            self.executionMode = executionMode
        }
    }
}
