// EllipticCurveDigitalSignatureAlgorithmModel+Message.swift

extension EllipticCurveDigitalSignatureAlgorithmModel {
    internal struct Message {
        let representation: Representation
        
        init(representation: Representation) {
            self.representation = representation
        }
    }
}
