// SchnorrBatchVerificationExecutionCallRecorder.swift

actor SchnorrBatchVerificationExecutionCallRecorder {
    private(set) var cpuRecordCounts: [Int] = []
    private(set) var metalRecordCounts: [Int] = []
    private(set) var partialMetalResultCounts: [Int] = []

    func recordCPUExecution(recordCount: Int) {
        cpuRecordCounts.append(recordCount)
    }

    func recordMetalExecution(recordCount: Int) {
        metalRecordCounts.append(recordCount)
    }

    func recordPartialMetalResults(resultCount: Int) {
        partialMetalResultCounts.append(resultCount)
    }
}
