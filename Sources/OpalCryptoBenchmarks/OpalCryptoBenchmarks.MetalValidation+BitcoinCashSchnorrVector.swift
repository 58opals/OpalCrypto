// OpalCryptoBenchmarks.MetalValidation+BitcoinCashSchnorrVector.swift

extension OpalCryptoBenchmarks.MetalValidation {
    struct BitcoinCashSchnorrVector {
        let publicKeyHex: String
        let digestHex: String
        let signatureHex: String
        let expected: Bool
        let isMetalPreparable: Bool

        init(
            publicKeyHex: String,
            digestHex: String,
            signatureHex: String,
            expected: Bool,
            isMetalPreparable: Bool = true
        ) {
            self.publicKeyHex = publicKeyHex
            self.digestHex = digestHex
            self.signatureHex = signatureHex
            self.expected = expected
            self.isMetalPreparable = isMetalPreparable
        }
    }
}
