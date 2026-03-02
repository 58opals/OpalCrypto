// Unsigned512BitIntegerModel+.swift

extension Unsigned512BitIntegerModel: Equatable {
    internal static func == (lhs: Unsigned512BitIntegerModel, rhs: Unsigned512BitIntegerModel) -> Bool {
        lhs.limbs[0] == rhs.limbs[0]
        && lhs.limbs[1] == rhs.limbs[1]
        && lhs.limbs[2] == rhs.limbs[2]
        && lhs.limbs[3] == rhs.limbs[3]
        && lhs.limbs[4] == rhs.limbs[4]
        && lhs.limbs[5] == rhs.limbs[5]
        && lhs.limbs[6] == rhs.limbs[6]
        && lhs.limbs[7] == rhs.limbs[7]
    }
}
