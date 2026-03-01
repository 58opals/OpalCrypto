// Unsigned256BitIntegerModel+.swift

extension Unsigned256BitIntegerModel: Equatable {
    public static func == (lhs: Unsigned256BitIntegerModel, rhs: Unsigned256BitIntegerModel) -> Bool {
        lhs.limbs[0] == rhs.limbs[0]
        && lhs.limbs[1] == rhs.limbs[1]
        && lhs.limbs[2] == rhs.limbs[2]
        && lhs.limbs[3] == rhs.limbs[3]
    }
}
