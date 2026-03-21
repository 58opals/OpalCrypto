// FieldElementModel+.swift

extension FieldElementModel {
    @inlinable
    func pow(exponentBits: [Bool]) -> FieldElementModel {
        var result = FieldElementModel.one
        for bit in exponentBits {
            result = result.square()
            if bit {
                result = result.mul(self)
            }
        }
        return result
    }

    @inlinable
    func pow(exponentNibbles: [UInt8]) -> FieldElementModel {
        var powerTable: InlineArray<16, FieldElementModel> = .init(repeating: .one)
        powerTable[1] = self
        if powerTable.count > 2 {
            for index in 2..<powerTable.count {
                powerTable[index] = powerTable[index - 1].mul(self)
            }
        }

        var result = FieldElementModel.one
        for nibble in exponentNibbles {
            result = result.square(4)
            if nibble != 0 {
                result = result.mul(powerTable[Int(nibble)])
            }
        }
        return result
    }

    @inlinable
    func sqrtUsingNibbleExponentiation() -> FieldElementModel? {
        let candidate = pow(exponentNibbles: FieldPowModel.squareRootExponentNibbles)
        guard candidate.square() == self else {
            return nil
        }
        return candidate
    }

    @inlinable
    var isQuadraticResidueUsingNibbleExponentiation: Bool {
        pow(exponentNibbles: FieldPowModel.legendreExponentNibbles) == .one
    }
    
    @inlinable
    func invert() -> FieldElementModel {
        return invertFast()
    }
    
    @inlinable
    func invertUsingExponentiation() -> FieldElementModel {
        pow(exponentBits: FieldPowModel.inversionExponentBits)
    }
}
