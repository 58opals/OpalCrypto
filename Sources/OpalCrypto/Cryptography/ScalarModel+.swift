// ScalarModel+.swift

extension ScalarModel {
    func square(_ count: Int) -> ScalarModel {
        var result = self
        for _ in 0..<count {
            result = result.mulModN(result)
        }
        return result
    }

    func pow(exponentBits: [Bool]) -> ScalarModel {
        var result = ScalarModel.one
        for bit in exponentBits {
            result = result.mulModN(result)
            if bit {
                result = result.mulModN(self)
            }
        }
        return result
    }

    func pow(exponentNibbles: [UInt8]) -> ScalarModel {
        var powerTable: InlineArray<16, ScalarModel> = .init(repeating: .one)
        powerTable[1] = self
        if powerTable.count > 2 {
            for index in 2..<powerTable.count {
                powerTable[index] = powerTable[index - 1].mulModN(self)
            }
        }

        var result = ScalarModel.one
        for nibble in exponentNibbles {
            result = result.square(4)
            if nibble != 0 {
                result = result.mulModN(powerTable[Int(nibble)])
            }
        }
        return result
    }
}
