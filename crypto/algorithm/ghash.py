# import external library
import numpy as np

# from import external library
from typing import Union

# from import internal library
from bitwise import Bitwise
from block_cipher_modes import SymmetricAlgorithm
from padding import Padding, PaddingScheme
from utility import Utility


class GHASH:
    # a polynomial in GF(2^128) is defined as:
    #       x[0] + x[1] α^1 + x[2] α^2 + . . . + x[127] α^127
    #           where ^ represents 'power'
    # while in number representation of 128 bits, msb will be treated as x[0] and lsb as x[127]

    R_4_bit = [
        0x00000000, 0x1C200000, 0x38400000, 0x24600000, 0x70800000, 0x6CA00000, 0x48C00000, 0x54E00000,
        0xE1000000, 0xFD200000, 0xD9400000, 0xC5600000, 0x91800000, 0x8DA00000, 0xA9C00000, 0xB5E00000
    ]

    R_8_bit = [
        0x00000000, 0x01C20000, 0x03840000, 0x02460000, 0x07080000, 0x06CA0000, 0x048C0000, 0x054E0000,
        0x0E100000, 0x0FD20000, 0x0D940000, 0x0C560000, 0x09180000, 0x08DA0000, 0x0A9C0000, 0x0B5E0000,
        0x1C200000, 0x1DE20000, 0x1FA40000, 0x1E660000, 0x1B280000, 0x1AEA0000, 0x18AC0000, 0x196E0000,
        0x12300000, 0x13F20000, 0x11B40000, 0x10760000, 0x15380000, 0x14FA0000, 0x16BC0000, 0x177E0000,
        0x38400000, 0x39820000, 0x3BC40000, 0x3A060000, 0x3F480000, 0x3E8A0000, 0x3CCC0000, 0x3D0E0000,
        0x36500000, 0x37920000, 0x35D40000, 0x34160000, 0x31580000, 0x309A0000, 0x32DC0000, 0x331E0000,
        0x24600000, 0x25A20000, 0x27E40000, 0x26260000, 0x23680000, 0x22AA0000, 0x20EC0000, 0x212E0000,
        0x2A700000, 0x2BB20000, 0x29F40000, 0x28360000, 0x2D780000, 0x2CBA0000, 0x2EFC0000, 0x2F3E0000,
        0x70800000, 0x71420000, 0x73040000, 0x72C60000, 0x77880000, 0x764A0000, 0x740C0000, 0x75CE0000,
        0x7E900000, 0x7F520000, 0x7D140000, 0x7CD60000, 0x79980000, 0x785A0000, 0x7A1C0000, 0x7BDE0000,
        0x6CA00000, 0x6D620000, 0x6F240000, 0x6EE60000, 0x6BA80000, 0x6A6A0000, 0x682C0000, 0x69EE0000,
        0x62B00000, 0x63720000, 0x61340000, 0x60F60000, 0x65B80000, 0x647A0000, 0x663C0000, 0x67FE0000,
        0x48C00000, 0x49020000, 0x4B440000, 0x4A860000, 0x4FC80000, 0x4E0A0000, 0x4C4C0000, 0x4D8E0000,
        0x46D00000, 0x47120000, 0x45540000, 0x44960000, 0x41D80000, 0x401A0000, 0x425C0000, 0x439E0000,
        0x54E00000, 0x55220000, 0x57640000, 0x56A60000, 0x53E80000, 0x522A0000, 0x506C0000, 0x51AE0000,
        0x5AF00000, 0x5B320000, 0x59740000, 0x58B60000, 0x5DF80000, 0x5C3A0000, 0x5E7C0000, 0x5FBE0000,
        0xE1000000, 0xE0C20000, 0xE2840000, 0xE3460000, 0xE6080000, 0xE7CA0000, 0xE58C0000, 0xE44E0000,
        0xEF100000, 0xEED20000, 0xEC940000, 0xED560000, 0xE8180000, 0xE9DA0000, 0xEB9C0000, 0xEA5E0000,
        0xFD200000, 0xFCE20000, 0xFEA40000, 0xFF660000, 0xFA280000, 0xFBEA0000, 0xF9AC0000, 0xF86E0000,
        0xF3300000, 0xF2F20000, 0xF0B40000, 0xF1760000, 0xF4380000, 0xF5FA0000, 0xF7BC0000, 0xF67E0000,
        0xD9400000, 0xD8820000, 0xDAC40000, 0xDB060000, 0xDE480000, 0xDF8A0000, 0xDDCC0000, 0xDC0E0000,
        0xD7500000, 0xD6920000, 0xD4D40000, 0xD5160000, 0xD0580000, 0xD19A0000, 0xD3DC0000, 0xD21E0000,
        0xC5600000, 0xC4A20000, 0xC6E40000, 0xC7260000, 0xC2680000, 0xC3AA0000, 0xC1EC0000, 0xC02E0000,
        0xCB700000, 0xCAB20000, 0xC8F40000, 0xC9360000, 0xCC780000, 0xCDBA0000, 0xCFFC0000, 0xCE3E0000,
        0x91800000, 0x90420000, 0x92040000, 0x93C60000, 0x96880000, 0x974A0000, 0x950C0000, 0x94CE0000,
        0x9F900000, 0x9E520000, 0x9C140000, 0x9DD60000, 0x98980000, 0x995A0000, 0x9B1C0000, 0x9ADE0000,
        0x8DA00000, 0x8C620000, 0x8E240000, 0x8FE60000, 0x8AA80000, 0x8B6A0000, 0x892C0000, 0x88EE0000,
        0x83B00000, 0x82720000, 0x80340000, 0x81F60000, 0x84B80000, 0x857A0000, 0x873C0000, 0x86FE0000,
        0xA9C00000, 0xA8020000, 0xAA440000, 0xAB860000, 0xAEC80000, 0xAF0A0000, 0xAD4C0000, 0xAC8E0000,
        0xA7D00000, 0xA6120000, 0xA4540000, 0xA5960000, 0xA0D80000, 0xA11A0000, 0xA35C0000, 0xA29E0000,
        0xB5E00000, 0xB4220000, 0xB6640000, 0xB7A60000, 0xB2E80000, 0xB32A0000, 0xB16C0000, 0xB0AE0000,
        0xBBF00000, 0xBA320000, 0xB8740000, 0xB9B60000, 0xBCF80000, 0xBD3A0000, 0xBF7C0000, 0xBEBE0000
    ]

    def __init__(self, algorithm: SymmetricAlgorithm):

        # create an algorithm instance
        SymmetricAlgorithm(algorithm)
        self.algorithm = algorithm.value()
        self._block_size = self.algorithm.get_block_size()
        self.encrypt_one_block = self.algorithm.get_encrypt_method()

        self.H = None
        self._iv = None

        # working numpy buffer
        self.src_temp = np.zeros((self._block_size,), dtype=np.uint8)
        self.R = 0xE1
        self.R_poly = np.uint16(0xE100)

        self.OPTIMIZE_LEVEL = ['no_tables', 'shoup_4_bit_tables', 'shoup_8_bit_tables',
                               'simple_4_bit_tables', 'simple_8_bit_tables']
        self._optimize = self.OPTIMIZE_LEVEL[1]

    def set_key(self, key: Union[str, np.ndarray]):
        self.algorithm.set_key(key)

        # allocate numpy buffer for H and iv
        self.H = np.zeros((self._block_size,), dtype=np.uint8)
        self._iv = np.zeros((self._block_size,), dtype=np.uint8)

        # compute H
        self.encrypt_one_block(self.H)

        # derive table to fast multiply by H
        if self._optimize == 'no_tables':
            pass
        else:
            _generate_table = eval(f'self._generate_table_for_{self._optimize}')
            _generate_table()

    def _multiply_by_alpha(self, output_data: np.ndarray, input_data: np.ndarray, input_rem: np.int16,
                           bit_mask, rem_mask) -> np.int16:
        output_data[:] = input_data[:]
        bit = self._shift_right(output_data)
        if bit:
            output_data[0] ^= self.R

        bit = input_rem & bit_mask
        output_rem = input_rem >> 1
        if bit:
            output_rem ^= self.R_poly

        return np.int16(output_rem & rem_mask)

    def _generate_table_for_shoup(self, bits):
        possible_values = 1 << bits
        self._M = np.zeros((possible_values, self._block_size), dtype=np.uint8)
        self._R = np.zeros((possible_values,), dtype=np.uint16)

        self._M[possible_values >> 1][:] = self.H[:]
        self._R[possible_values >> 1] = self.R_poly

        i = possible_values >> 2
        while i:
            self._R[i] = self._multiply_by_alpha(self._M[i], self._M[i << 1], self._R[i << 1],
                                                 bit_mask=0x0010, rem_mask=0xFFF0)
            i >>= 1

        i = 2
        while i < possible_values:
            for j in range(1, i):
                Bitwise.xor(self._M[i], self._M[j], out=self._M[i + j])
                self._R[i + j] = self._R[i] ^ self._R[j]
            i = i << 1

    def _generate_table_for_shoup_4_bit_tables(self):
        self._M = np.zeros((16, self._block_size), dtype=np.uint8)
        self._R = np.zeros((16,), dtype=np.uint16)

        # here 8 represents 1000, i.e., 1 . α^0 + 0 . α^1 + 0 . α^2 + 0 . α^3
        # => M[8]= M[1000] = 1 . H
        self._M[8][:] = self.H[:]
        self._R[8] = self.R_poly

        i = 4
        # calculate,
        #   M[4]= M[0100] = H . α^1 = M[1000] . α^1
        #   M[2]= M[0010] = H . α^2 = M[0100] . α^1
        #   M[1]= M[0001] = H . α^3 = M[0010] . α^1
        while i:
            self._R[i] = self._multiply_by_alpha(self._M[i], self._M[i << 1], self._R[i << 1],
                                                 bit_mask=0x0010, rem_mask=0xFFF0)
            i >>= 1

        i = 2
        # calculate,
        #   M[3] = M[0011] = M[0010] + M[0001] = M[2] + M[1]
        #   M[5] = M[0101] = M[0100] + M[0001] = M[4] + M[1]
        #   M[6] = M[0110] = M[0100] + M[0010] = M[4] + M[2]
        #   M[7] = M[0111] = M[0100] + M[0011] = M[4] + M[3]
        # ...
        while i < 16:
            for j in range(1, i):
                Bitwise.xor(self._M[i], self._M[j], out=self._M[i + j])
                self._R[i + j] = self._R[i] ^ self._R[j]
            i = i << 1

    def _generate_table_for_shoup_8_bit_tables(self):
        self._M = np.zeros((256, self._block_size), dtype=np.uint8)
        self._R = np.zeros((256,), dtype=np.uint16)

        self._M[128][:] = self.H[:]
        self._R[128] = self.R_poly

        i = 64
        while i:
            self._R[i] = self._multiply_by_alpha(self._M[i], self._M[i << 1], self._R[i << 1],
                                                 bit_mask=0x0001, rem_mask=0xFFFF)
            i >>= 1

        i = 2
        while i < 256:
            for j in range(1, i):
                Bitwise.xor(self._M[i], self._M[j], out=self._M[i + j])
                self._R[i + j] = self._R[i] ^ self._R[j]
            i = i << 1

    def _generate_table_for_simple_4_bit_tables(self):
        raise NotImplementedError('Yet to be implemented')

    def _generate_table_for_simple_8_bit_tables(self):
        raise NotImplementedError('Yet to be implemented')

    @staticmethod
    def _shift_right(x: np.ndarray):
        bit = 0

        for i in range(len(x)):
            temp = (bit << 7) | (x[i] >> 1)
            bit = x[i] & 1
            x[i] = temp

        return bit

    @staticmethod
    def _shift_right_byte(x: np.ndarray):
        temp = x[-1]

        for i in range(len(x) - 1, 0, -1):
            x[i] = x[i - 1]

        x[0] = 0
        return temp

    @staticmethod
    def _shift_right_nibble(x: np.ndarray):
        bit = 0

        for i in range(len(x)):
            temp = (bit << 4) | (x[i] >> 4)
            bit = x[i] & 0xF
            x[i] = temp

        return bit

    @staticmethod
    def _shift_left_byte(x: np.ndarray):
        temp = x[0]

        for i in range(len(x) - 1):
            x[i] = x[i + 1]

        x[len(x) - 1] = 0
        return temp

    def _multiply(self, x: np.ndarray, y: np.ndarray, out: np.ndarray):
        z = np.zeros((self._block_size,), dtype=np.uint8)
        v = y.copy()

        for i in range(128):
            j = i // 8
            m = 1 << (7 - (i & 7))

            # add polynomial to result if bit is set
            if x[j] & m:
                Bitwise.xor(z, v, z)

            # multiply by α
            bit = self._shift_right(v)

            # reduce polynomial if α^128 in above result
            if bit:
                v[0] ^= self.R

        out[:] = z[:]

    def _multiply_using_shoup_4_bit_tables(self, data: np.ndarray):
        z = np.zeros((self._block_size,), dtype=np.uint8)
        v = data.copy()

        for i in range(15, -1, -1):
            #
            # low nibble
            #

            # multiply by α^4
            a = self._shift_right_nibble(z)

            # Z ← Z ⊕ M[byte(X,i)]
            Bitwise.xor(z, self._M[v[i] & 0x0F], z)

            # reduce the above result based on the value of 'a'
            rem = self._R[a]

            z[0] ^= rem >> 8
            z[1] ^= rem & 0xFF

            #
            # high nibble
            #

            # multiply by α^4
            a = self._shift_right_nibble(z)

            # Z ← Z ⊕ M[byte(X,i)]
            Bitwise.xor(z, self._M[v[i] >> 4], z)

            # reduce the above result based on the value of 'a'
            rem = self._R[a]

            z[0] ^= rem >> 8
            z[1] ^= rem & 0xFF

        data[:] = z[:]

    def _multiply_using_shoup_8_bit_tables(self, data: np.ndarray):
        z = np.zeros((self._block_size,), dtype=np.uint8)
        v = data.copy()

        for i in range(15, -1, -1):
            # multiply by α^8
            a = self._shift_right_byte(z)

            # Z ← Z ⊕ M[byte(X,i)]
            Bitwise.xor(z, self._M[v[i]], z)

            # reduce the above result based on the value of 'a'
            rem = self._R[a]

            z[0] ^= rem >> 8
            z[1] ^= rem & 0xFF

        data[:] = z[:]

    def _multiply_using_simple_4_bit_tables(self, data: np.ndarray):
        raise NotImplementedError('Yet to be implemented')

    def _multiply_using_simple_8_bit_tables(self, data: np.ndarray):
        raise NotImplementedError('Yet to be implemented')

    def _multiply_h(self, data: np.ndarray):
        if self._optimize == 'no_tables':
            self._multiply(data, self.H, data)
        else:
            _multiply = eval(f'self._multiply_using_{self._optimize}')
            _multiply(data)

    def generate(
            self,
            input_data: Union[str, np.ndarray],
            final: bool = False,
            hash_: np.ndarray = None
    ) -> Union[str, np.ndarray]:
        # copy input to output for further calculation
        output_data = Utility.copy_to_numpy(input_data, error_msg='Invalid plaintext')

        if final:
            output_data = Padding(PaddingScheme.M1, self._block_size).apply_padding(output_data)

        if len(output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes).')

        # calculate number of complete blocks
        no_of_blocks = len(output_data) // self._block_size

        # process each block
        for i in range(no_of_blocks):
            _start = i * self._block_size
            _end = _start + self._block_size

            Bitwise.xor(self._iv, output_data[_start: _end], self.src_temp)
            self._multiply_h(self.src_temp)
            self._iv[:] = self.src_temp[:]

        if final:
            # copy output in passed output data buffer
            if hash_ is not None:
                hash_[:] = self._iv[:]
            else:
                hash_ = self._iv.copy()

            # return output in same format as input
            if isinstance(input_data, str):
                return Utility.convert_to_str(self._iv[:])
        else:
            if isinstance(input_data, str):
                return ''

        return hash_
