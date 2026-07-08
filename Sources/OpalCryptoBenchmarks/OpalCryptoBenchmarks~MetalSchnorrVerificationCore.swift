// OpalCryptoBenchmarks~MetalSchnorrVerificationCore.swift

import Foundation
import OpalCrypto

#if canImport(Metal)
import Metal
#endif

extension OpalCryptoBenchmarks {
    enum MetalSchnorrVerificationCore {
        static func run(
            input: MetalSchnorrVerificationBenchmarkInput,
            count: Int
        ) throws -> Int {
            #if canImport(Metal)
            let recordWords = makeRecordWords(input: input, count: count)
            let digitWords = makeDigitWords(input: input, count: count)
            return try MetalSchnorrVerificationRuntime.shared.run(
                recordWords: recordWords,
                digitWords: digitWords,
                tableWords: input.windowedNonAdjacentFormTableWords,
                expectedResults: Array(repeating: input.expected ? 1 : 0, count: count),
                recordCount: count
            )
            #else
            throw MetalVerificationProbeError.unavailable
            #endif
        }

        static func run(batchInput: MetalSchnorrVerificationBatchBenchmarkInput) throws -> Int {
            #if canImport(Metal)
            try MetalSchnorrVerificationRuntime.shared.run(
                recordWords: batchInput.signatureXWords,
                digitWords: batchInput.windowedNonAdjacentFormDigits,
                tableWords: batchInput.windowedNonAdjacentFormTableWords,
                expectedResults: batchInput.expectedResults,
                recordCount: batchInput.recordCount
            )
            #else
            throw MetalVerificationProbeError.unavailable
            #endif
        }

        private static func makeRecordWords(
            input: MetalSchnorrVerificationBenchmarkInput,
            count: Int
        ) -> [UInt32] {
            var words: [UInt32] = .init()
            words.reserveCapacity(count * 8)
            for _ in 0..<count {
                words.append(contentsOf: input.signatureXWords)
            }
            return words
        }

        private static func makeDigitWords(
            input: MetalSchnorrVerificationBenchmarkInput,
            count: Int
        ) -> [Int32] {
            var words: [Int32] = .init()
            words.reserveCapacity(count * input.windowedNonAdjacentFormDigits.count)
            for _ in 0..<count {
                words.append(contentsOf: input.windowedNonAdjacentFormDigits)
            }
            return words
        }
    }
}

#if canImport(Metal)
private final class MetalSchnorrVerificationRuntime: @unchecked Sendable {
    static let shared = try! MetalSchnorrVerificationRuntime()

    private let device: MTLDevice
    private let commandQueue: MTLCommandQueue
    private let pipelineState: MTLComputePipelineState

    private init() throws {
        guard let device = MTLCreateSystemDefaultDevice(),
              let commandQueue = device.makeCommandQueue()
        else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }
        self.device = device
        self.commandQueue = commandQueue
        let library = try device.makeLibrary(
            source: Self.kernelSource,
            options: nil
        )
        guard let function = library.makeFunction(name: "opal_schnorr_verify_core") else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }
        pipelineState = try device.makeComputePipelineState(function: function)
    }

    func run(
        recordWords: [UInt32],
        digitWords: [Int32],
        tableWords: [UInt32],
        expectedResults: [UInt32],
        recordCount: Int
    ) throws -> Int {
        guard recordCount > 0 else { return 0 }
        precondition(recordWords.count == recordCount * 8)
        precondition(digitWords.count == recordCount * 4 * 130)
        precondition(expectedResults.count == recordCount)

        guard let inputBuffer = device.makeBuffer(
            bytes: recordWords,
            length: recordWords.count * MemoryLayout<UInt32>.stride,
            options: .storageModeShared
        ),
            let digitBuffer = device.makeBuffer(
                bytes: digitWords,
                length: digitWords.count * MemoryLayout<Int32>.stride,
                options: .storageModeShared
            ),
            let tableBuffer = device.makeBuffer(
                bytes: tableWords,
                length: tableWords.count * MemoryLayout<UInt32>.stride,
                options: .storageModeShared
            ),
            let outputBuffer = device.makeBuffer(
                length: recordCount * MemoryLayout<UInt32>.stride,
                options: .storageModeShared
            )
        else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }

        var countValue = UInt32(recordCount)
        guard let countBuffer = device.makeBuffer(
            bytes: &countValue,
            length: MemoryLayout<UInt32>.stride,
            options: .storageModeShared
        ),
            let commandBuffer = commandQueue.makeCommandBuffer(),
            let encoder = commandBuffer.makeComputeCommandEncoder()
        else {
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.unavailable
        }

        encoder.setComputePipelineState(pipelineState)
        encoder.setBuffer(inputBuffer, offset: 0, index: 0)
        encoder.setBuffer(outputBuffer, offset: 0, index: 1)
        encoder.setBuffer(countBuffer, offset: 0, index: 2)
        encoder.setBuffer(tableBuffer, offset: 0, index: 3)
        encoder.setBuffer(digitBuffer, offset: 0, index: 4)

        let threadCount = MTLSize(width: recordCount, height: 1, depth: 1)
        let threadsPerThreadgroup = MTLSize(
            width: min(recordCount, pipelineState.maxTotalThreadsPerThreadgroup),
            height: 1,
            depth: 1
        )
        encoder.dispatchThreads(
            threadCount,
            threadsPerThreadgroup: threadsPerThreadgroup
        )
        encoder.endEncoding()
        commandBuffer.commit()
        commandBuffer.waitUntilCompleted()

        if commandBuffer.status == .error {
            let message = commandBuffer.error?.localizedDescription ?? "unknown error"
            throw OpalCryptoBenchmarks.MetalVerificationProbeError.commandBufferFailed(message)
        }

        let output = outputBuffer.contents().bindMemory(
            to: UInt32.self,
            capacity: recordCount
        )
        var checksum = 0
        for index in 0..<recordCount {
            guard output[index] == expectedResults[index] else {
                throw OpalCryptoBenchmarks.MetalVerificationProbeError.invalidResult(index: index)
            }
            checksum ^= Int(output[index]) &+ index
        }
        return checksum
    }

    private static let kernelSource = """
    #include <metal_stdlib>
    using namespace metal;

    struct U256 {
        uint v[8];
    };

    struct AddResult {
        U256 value;
        uint carry;
    };

    struct SubResult {
        U256 value;
        uint borrow;
    };

    struct Point {
        U256 x;
        U256 y;
        U256 z;
        bool infinity;
    };

    inline U256 u256_zero() {
        U256 r;
        for (uint i = 0; i < 8; i++) {
            r.v[i] = 0u;
        }
        return r;
    }

    inline U256 u256_one() {
        U256 r = u256_zero();
        r.v[0] = 1u;
        return r;
    }

    inline U256 field_p() {
        U256 r;
        r.v[0] = 0xfffffc2fu;
        r.v[1] = 0xfffffffeu;
        r.v[2] = 0xffffffffu;
        r.v[3] = 0xffffffffu;
        r.v[4] = 0xffffffffu;
        r.v[5] = 0xffffffffu;
        r.v[6] = 0xffffffffu;
        r.v[7] = 0xffffffffu;
        return r;
    }

    inline U256 legendre_exponent() {
        U256 r;
        r.v[0] = 0x7ffffe17u;
        r.v[1] = 0xffffffffu;
        r.v[2] = 0xffffffffu;
        r.v[3] = 0xffffffffu;
        r.v[4] = 0xffffffffu;
        r.v[5] = 0xffffffffu;
        r.v[6] = 0xffffffffu;
        r.v[7] = 0x7fffffffu;
        return r;
    }

    inline int u256_cmp(U256 a, U256 b) {
        for (int i = 7; i >= 0; i--) {
            if (a.v[i] < b.v[i]) {
                return -1;
            }
            if (a.v[i] > b.v[i]) {
                return 1;
            }
        }
        return 0;
    }

    inline bool u256_equal(U256 a, U256 b) {
        uint difference = 0u;
        for (uint i = 0; i < 8; i++) {
            difference |= a.v[i] ^ b.v[i];
        }
        return difference == 0u;
    }

    inline bool u256_is_zero(U256 a) {
        uint combined = 0u;
        for (uint i = 0; i < 8; i++) {
            combined |= a.v[i];
        }
        return combined == 0u;
    }

    inline bool u256_bit(U256 a, int bit) {
        uint wordIndex = uint(bit) >> 5;
        uint shift = uint(bit) & 31u;
        return ((a.v[wordIndex] >> shift) & 1u) != 0u;
    }

    inline AddResult u256_add_raw(U256 a, U256 b) {
        AddResult result;
        ulong carry = 0ul;
        for (uint i = 0; i < 8; i++) {
            ulong sum = ulong(a.v[i]) + ulong(b.v[i]) + carry;
            result.value.v[i] = uint(sum & 0xfffffffful);
            carry = sum >> 32;
        }
        result.carry = uint(carry);
        return result;
    }

    inline SubResult u256_sub_raw(U256 a, U256 b) {
        SubResult result;
        ulong borrow = 0ul;
        for (uint i = 0; i < 8; i++) {
            ulong left = ulong(a.v[i]);
            ulong right = ulong(b.v[i]) + borrow;
            if (left < right) {
                result.value.v[i] = uint((0x100000000ul + left - right) & 0xfffffffful);
                borrow = 1ul;
            } else {
                result.value.v[i] = uint(left - right);
                borrow = 0ul;
            }
        }
        result.borrow = uint(borrow);
        return result;
    }

    inline U256 field_normalize(U256 value) {
        U256 p = field_p();
        U256 result = value;
        for (uint i = 0; i < 16; i++) {
            if (u256_cmp(result, p) < 0) {
                return result;
            }
            result = u256_sub_raw(result, p).value;
        }
        return result;
    }

    inline U256 field_add(U256 a, U256 b) {
        U256 p = field_p();
        AddResult added = u256_add_raw(a, b);
        U256 result = added.value;
        if (added.carry != 0u || u256_cmp(result, p) >= 0) {
            result = u256_sub_raw(result, p).value;
        }
        return result;
    }

    inline U256 field_sub(U256 a, U256 b) {
        U256 p = field_p();
        SubResult subtracted = u256_sub_raw(a, b);
        U256 result = subtracted.value;
        if (subtracted.borrow != 0u) {
            result = u256_add_raw(result, p).value;
        }
        return result;
    }

    inline U256 field_negate(U256 value) {
        if (u256_is_zero(value)) {
            return value;
        }
        return field_sub(u256_zero(), value);
    }

    inline U256 field_double(U256 a) {
        return field_add(a, a);
    }

    inline void add_limb(thread ulong *limbs, uint index, ulong value) {
        ulong carry = value;
        uint cursor = index;
        while (carry != 0ul && cursor < 24u) {
            ulong low = carry & 0xfffffffful;
            ulong sum = limbs[cursor] + low;
            limbs[cursor] = sum & 0xfffffffful;
            carry = (carry >> 32) + (sum >> 32);
            cursor += 1u;
        }
    }

    inline U256 field_mul(U256 a, U256 b) {
        ulong limbs[24];
        for (uint i = 0; i < 24; i++) {
            limbs[i] = 0ul;
        }
        for (uint i = 0; i < 8; i++) {
            for (uint j = 0; j < 8; j++) {
                add_limb(limbs, i + j, ulong(a.v[i]) * ulong(b.v[j]));
            }
        }
        for (uint pass = 0; pass < 4; pass++) {
            for (uint index = 8; index < 24; index++) {
                ulong high = limbs[index];
                if (high == 0ul) {
                    continue;
                }
                limbs[index] = 0ul;
                add_limb(limbs, index - 8u, high * 977ul);
                add_limb(limbs, index - 7u, high);
            }
        }
        U256 result;
        for (uint i = 0; i < 8; i++) {
            result.v[i] = uint(limbs[i]);
        }
        return field_normalize(result);
    }

    inline U256 field_square(U256 a) {
        return field_mul(a, a);
    }

    inline uint u256_window4(U256 scalar, uint window) {
        uint wordIndex = window >> 3;
        uint shift = (window & 7u) << 2;
        return (scalar.v[wordIndex] >> shift) & 0x0fu;
    }

    inline U256 field_square_four_times(U256 value) {
        value = field_square(value);
        value = field_square(value);
        value = field_square(value);
        return field_square(value);
    }

    inline U256 field_pow_window4(U256 base, U256 exponent) {
        U256 powerTable[16];
        powerTable[0] = u256_one();
        powerTable[1] = base;
        for (uint index = 2; index < 16; index++) {
            powerTable[index] = field_mul(powerTable[index - 1u], base);
        }

        U256 result = u256_one();
        for (int window = 63; window >= 0; window--) {
            result = field_square_four_times(result);
            uint digit = u256_window4(exponent, uint(window));
            if (digit != 0u) {
                result = field_mul(result, powerTable[digit]);
            }
        }
        return result;
    }

    inline bool field_is_quadratic_residue(U256 value) {
        if (u256_is_zero(value)) {
            return true;
        }
        return u256_equal(field_pow_window4(value, legendre_exponent()), u256_one());
    }

    inline Point point_infinity() {
        Point point;
        point.x = u256_zero();
        point.y = u256_zero();
        point.z = u256_zero();
        point.infinity = true;
        return point;
    }

    inline Point point_from_affine(U256 x, U256 y) {
        Point point;
        point.x = x;
        point.y = y;
        point.z = u256_one();
        point.infinity = false;
        return point;
    }

    inline Point point_double(Point point) {
        if (point.infinity || u256_is_zero(point.y)) {
            return point_infinity();
        }

        U256 xSquared = field_square(point.x);
        U256 ySquared = field_square(point.y);
        U256 yFourth = field_square(ySquared);
        U256 yFourthTimesEight = field_double(field_double(field_double(yFourth)));
        U256 xPlusYSquared = field_add(point.x, ySquared);
        U256 delta = field_double(field_sub(field_sub(field_square(xPlusYSquared), xSquared), yFourth));
        U256 threeX = field_add(field_double(xSquared), xSquared);
        U256 resultX = field_sub(field_square(threeX), field_double(delta));
        U256 resultY = field_sub(field_mul(threeX, field_sub(delta, resultX)), yFourthTimesEight);
        U256 resultZ = field_double(field_mul(point.y, point.z));

        Point result;
        result.x = resultX;
        result.y = resultY;
        result.z = resultZ;
        result.infinity = false;
        return result;
    }

    inline Point point_add_affine(Point point, U256 otherX, U256 otherY) {
        if (point.infinity) {
            return point_from_affine(otherX, otherY);
        }

        U256 zSquared = field_square(point.z);
        U256 otherXAdjusted = field_mul(otherX, zSquared);
        U256 otherYAdjusted = field_mul(otherY, field_mul(zSquared, point.z));
        U256 xDifference = field_sub(otherXAdjusted, point.x);
        U256 yDifference = field_sub(otherYAdjusted, point.y);

        if (u256_is_zero(xDifference)) {
            return u256_is_zero(yDifference) ? point_double(point) : point_infinity();
        }

        U256 xDifferenceSquared = field_square(xDifference);
        U256 xDifferenceCubed = field_mul(xDifference, xDifferenceSquared);
        U256 xProduct = field_mul(point.x, xDifferenceSquared);

        U256 resultX = field_sub(field_sub(field_square(yDifference), xDifferenceCubed), field_double(xProduct));
        U256 resultY = field_sub(field_mul(yDifference, field_sub(xProduct, resultX)), field_mul(point.y, xDifferenceCubed));
        U256 resultZ = field_mul(point.z, xDifference);

        Point result;
        result.x = resultX;
        result.y = resultY;
        result.z = resultZ;
        result.infinity = false;
        return result;
    }

    inline Point point_add(Point first, Point second) {
        if (first.infinity) {
            return second;
        }
        if (second.infinity) {
            return first;
        }

        U256 firstZSquared = field_square(first.z);
        U256 secondZSquared = field_square(second.z);
        U256 firstXAdjusted = field_mul(first.x, secondZSquared);
        U256 secondXAdjusted = field_mul(second.x, firstZSquared);
        U256 firstZCubed = field_mul(firstZSquared, first.z);
        U256 secondZCubed = field_mul(secondZSquared, second.z);
        U256 firstYAdjusted = field_mul(first.y, secondZCubed);
        U256 secondYAdjusted = field_mul(second.y, firstZCubed);

        if (u256_equal(firstXAdjusted, secondXAdjusted)) {
            if (!u256_equal(firstYAdjusted, secondYAdjusted)) {
                return point_infinity();
            }
            return point_double(first);
        }

        U256 xDifference = field_sub(secondXAdjusted, firstXAdjusted);
        U256 xDifferenceSquared = field_square(field_double(xDifference));
        U256 xDifferenceCubed = field_mul(xDifference, xDifferenceSquared);
        U256 yDifference = field_double(field_sub(secondYAdjusted, firstYAdjusted));
        U256 firstProduct = field_mul(firstXAdjusted, xDifferenceSquared);
        U256 resultX = field_sub(field_sub(field_square(yDifference), xDifferenceCubed), field_double(firstProduct));
        U256 resultY = field_sub(
            field_mul(yDifference, field_sub(firstProduct, resultX)),
            field_double(field_mul(firstYAdjusted, xDifferenceCubed))
        );
        U256 resultZ = field_mul(
            field_sub(field_sub(field_square(field_add(first.z, second.z)), firstZSquared), secondZSquared),
            xDifference
        );

        Point result;
        result.x = resultX;
        result.y = resultY;
        result.z = resultZ;
        result.infinity = false;
        return result;
    }

    inline U256 read_u256(device const uint *records, uint base) {
        U256 value;
        for (uint i = 0; i < 8; i++) {
            value.v[i] = records[base + i];
        }
        return value;
    }

    inline U256 read_table_u256(device const uint *tables, uint tableBase, uint tableIndex, uint coordinateOffset) {
        U256 value;
        uint base = tableBase + (tableIndex * 16u) + coordinateOffset;
        for (uint i = 0; i < 8; i++) {
            value.v[i] = tables[base + i];
        }
        return value;
    }

    inline int read_wnaf_digit(device const int *digits, uint recordIndex, uint component, uint index) {
        return digits[((recordIndex * 4u + component) * 130u) + index];
    }

    inline Point add_wnaf_digit(Point result, device const uint *tables, uint component, int digit) {
        if (digit == 0) {
            return result;
        }
        int magnitude = digit < 0 ? -digit : digit;
        uint tableIndex = uint(magnitude >> 1);
        uint tableBase = component * 512u;
        U256 x = read_table_u256(tables, tableBase, tableIndex, 0u);
        U256 y = read_table_u256(tables, tableBase, tableIndex, 8u);
        if (digit < 0) {
            y = field_negate(y);
        }
        return point_add_affine(result, x, y);
    }

    inline Point scalar_mul_wnaf(device const uint *tables, device const int *digits, uint recordIndex) {
        Point result = point_infinity();
        for (int index = 129; index >= 0; index--) {
            result = point_double(result);
            uint digitIndex = uint(index);
            result = add_wnaf_digit(result, tables, 0u, read_wnaf_digit(digits, recordIndex, 0u, digitIndex));
            result = add_wnaf_digit(result, tables, 1u, read_wnaf_digit(digits, recordIndex, 1u, digitIndex));
            result = add_wnaf_digit(result, tables, 2u, read_wnaf_digit(digits, recordIndex, 2u, digitIndex));
            result = add_wnaf_digit(result, tables, 3u, read_wnaf_digit(digits, recordIndex, 3u, digitIndex));
        }
        return result;
    }

    inline bool verify_schnorr_record(
        device const uint *records,
        device const uint *tables,
        device const int *digits,
        uint recordIndex,
        uint base
    ) {
        U256 signatureX = read_u256(records, base);

        Point candidate = scalar_mul_wnaf(tables, digits, recordIndex);
        if (candidate.infinity) {
            return false;
        }
        U256 zSquared = field_square(candidate.z);
        U256 expectedX = field_mul(signatureX, zSquared);
        if (!u256_equal(candidate.x, expectedX)) {
            return false;
        }
        U256 jacobiCandidate = field_mul(candidate.y, candidate.z);
        return field_is_quadratic_residue(jacobiCandidate);
    }

    kernel void opal_schnorr_verify_core(
        device const uint *records [[buffer(0)]],
        device uint *output [[buffer(1)]],
        constant uint &recordCount [[buffer(2)]],
        device const uint *tables [[buffer(3)]],
        device const int *digits [[buffer(4)]],
        uint id [[thread_position_in_grid]]
    ) {
        if (id >= recordCount) {
            return;
        }
        uint base = id * 8u;
        output[id] = verify_schnorr_record(records, tables, digits, id, base) ? 1u : 0u;
    }
    """
}
#endif
