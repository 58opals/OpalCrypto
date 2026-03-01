import Foundation
import Testing
import OpalCrypto

@Suite("Schnorr signature validation")
struct SchnorrSignatureValidator {
    @Test("Create signature from sixty-four bytes")
    func createSignatureFromSixtyFourBytes() throws {
        let payload = Data((0..<64).map { UInt8($0) })
        let signature = try SchnorrSignatureModel.Signature(raw64: payload)

        #expect(signature.r == Data(payload.prefix(32)))
        #expect(signature.s == Data(payload.suffix(32)))
        #expect(signature.raw64 == payload)
    }

    @Test("Reject raw signature payload with invalid length")
    func rejectRawSignaturePayloadWithInvalidLength() {
        let payload = Data(repeating: 0xAB, count: 63)
        do {
            _ = try SchnorrSignatureModel.Signature(raw64: payload)
            Issue.record("Expected invalid signature length error.")
        } catch let error as SchnorrSignatureModel.Error {
            #expect(error == .invalidSignatureLength(actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }

    @Test("Reject split signature payload with invalid length")
    func rejectSplitSignaturePayloadWithInvalidLength() {
        let signatureRComponent = Data(repeating: 0x01, count: 31)
        let signatureSComponent = Data(repeating: 0x02, count: 32)
        do {
            _ = try SchnorrSignatureModel.Signature(r: signatureRComponent, s: signatureSComponent)
            Issue.record("Expected invalid signature length error.")
        } catch let error as SchnorrSignatureModel.Error {
            #expect(error == .invalidSignatureLength(actual: 63))
        } catch {
            Issue.record("Unexpected error type: \(error)")
        }
    }
}
