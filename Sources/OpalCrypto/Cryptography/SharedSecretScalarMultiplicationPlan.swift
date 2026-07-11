// SharedSecretScalarMultiplicationPlan.swift

struct SharedSecretScalarMultiplicationPlan: Sendable {
    let primaryDigits: SignedScalar128Model.WindowedNonAdjacentForm
    let secondaryDigits: SignedScalar128Model.WindowedNonAdjacentForm

    init(privateKeyScalar: ScalarModel) {
        let scalarSplit = privateKeyScalar.splitForEndomorphism()
        primaryDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            scalarSplit.firstScalar,
            width: ScalarMultiplicationModel.verificationKeyWindowedNonAdjacentFormWidth
        )
        secondaryDigits = SignedScalar128Model.makeWindowedNonAdjacentForm(
            scalarSplit.secondScalar,
            width: ScalarMultiplicationModel.verificationKeyWindowedNonAdjacentFormWidth
        )
    }
}
