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
    #       x[0] + x[1] • α^1 + x[2] • α^2 + . . . + x[127] • α^127
    #           where ^ represents 'power'
    # while in number representation of 128 bits, msb will be treated as x[0] and lsb as x[127]

    R_4_bit = [
        0x0000, 0x1C20, 0x3840, 0x2460, 0x7080, 0x6CA0, 0x48C0, 0x54E0,
        0xE100, 0xFD20, 0xD940, 0xC560, 0x9180, 0x8DA0, 0xA9C0, 0xB5E0
    ]

    R_8_bit = [
        0x0000, 0x01C2, 0x0384, 0x0246, 0x0708, 0x06CA, 0x048C, 0x054E,
        0x0E10, 0x0FD2, 0x0D94, 0x0C56, 0x0918, 0x08DA, 0x0A9C, 0x0B5E,
        0x1C20, 0x1DE2, 0x1FA4, 0x1E66, 0x1B28, 0x1AEA, 0x18AC, 0x196E,
        0x1230, 0x13F2, 0x11B4, 0x1076, 0x1538, 0x14FA, 0x16BC, 0x177E,
        0x3840, 0x3982, 0x3BC4, 0x3A06, 0x3F48, 0x3E8A, 0x3CCC, 0x3D0E,
        0x3650, 0x3792, 0x35D4, 0x3416, 0x3158, 0x309A, 0x32DC, 0x331E,
        0x2460, 0x25A2, 0x27E4, 0x2626, 0x2368, 0x22AA, 0x20EC, 0x212E,
        0x2A70, 0x2BB2, 0x29F4, 0x2836, 0x2D78, 0x2CBA, 0x2EFC, 0x2F3E,
        0x7080, 0x7142, 0x7304, 0x72C6, 0x7788, 0x764A, 0x740C, 0x75CE,
        0x7E90, 0x7F52, 0x7D14, 0x7CD6, 0x7998, 0x785A, 0x7A1C, 0x7BDE,
        0x6CA0, 0x6D62, 0x6F24, 0x6EE6, 0x6BA8, 0x6A6A, 0x682C, 0x69EE,
        0x62B0, 0x6372, 0x6134, 0x60F6, 0x65B8, 0x647A, 0x663C, 0x67FE,
        0x48C0, 0x4902, 0x4B44, 0x4A86, 0x4FC8, 0x4E0A, 0x4C4C, 0x4D8E,
        0x46D0, 0x4712, 0x4554, 0x4496, 0x41D8, 0x401A, 0x425C, 0x439E,
        0x54E0, 0x5522, 0x5764, 0x56A6, 0x53E8, 0x522A, 0x506C, 0x51AE,
        0x5AF0, 0x5B32, 0x5974, 0x58B6, 0x5DF8, 0x5C3A, 0x5E7C, 0x5FBE,
        0xE100, 0xE0C2, 0xE284, 0xE346, 0xE608, 0xE7CA, 0xE58C, 0xE44E,
        0xEF10, 0xEED2, 0xEC94, 0xED56, 0xE818, 0xE9DA, 0xEB9C, 0xEA5E,
        0xFD20, 0xFCE2, 0xFEA4, 0xFF66, 0xFA28, 0xFBEA, 0xF9AC, 0xF86E,
        0xF330, 0xF2F2, 0xF0B4, 0xF176, 0xF438, 0xF5FA, 0xF7BC, 0xF67E,
        0xD940, 0xD882, 0xDAC4, 0xDB06, 0xDE48, 0xDF8A, 0xDDCC, 0xDC0E,
        0xD750, 0xD692, 0xD4D4, 0xD516, 0xD058, 0xD19A, 0xD3DC, 0xD21E,
        0xC560, 0xC4A2, 0xC6E4, 0xC726, 0xC268, 0xC3AA, 0xC1EC, 0xC02E,
        0xCB70, 0xCAB2, 0xC8F4, 0xC936, 0xCC78, 0xCDBA, 0xCFFC, 0xCE3E,
        0x9180, 0x9042, 0x9204, 0x93C6, 0x9688, 0x974A, 0x950C, 0x94CE,
        0x9F90, 0x9E52, 0x9C14, 0x9DD6, 0x9898, 0x995A, 0x9B1C, 0x9ADE,
        0x8DA0, 0x8C62, 0x8E24, 0x8FE6, 0x8AA8, 0x8B6A, 0x892C, 0x88EE,
        0x83B0, 0x8272, 0x8034, 0x81F6, 0x84B8, 0x857A, 0x873C, 0x86FE,
        0xA9C0, 0xA802, 0xAA44, 0xAB86, 0xAEC8, 0xAF0A, 0xAD4C, 0xAC8E,
        0xA7D0, 0xA612, 0xA454, 0xA596, 0xA0D8, 0xA11A, 0xA35C, 0xA29E,
        0xB5E0, 0xB422, 0xB664, 0xB7A6, 0xB2E8, 0xB32A, 0xB16C, 0xB0AE,
        0xBBF0, 0xBA32, 0xB874, 0xB9B6, 0xBCF8, 0xBD3A, 0xBF7C, 0xBEBE
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
        self._optimize = self.OPTIMIZE_LEVEL[2]

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
        # copy the input to output
        output_data[:] = input_data[:]

        # multiply by α with mod Irreducible Polynomial
        bit = self._shift_right(output_data)
        if bit:
            output_data[0] ^= self.R

        # remainder when multiply by α with mod Irreducible Polynomial
        bit = input_rem & bit_mask
        output_rem = input_rem >> 1
        if bit:
            output_rem ^= self.R_poly

        return np.int16(output_rem & rem_mask)

    def _generate_table_for_shoup_4_bit_tables(self):
        self._M = np.zeros((16, self._block_size), dtype=np.uint8)
        self._R = np.zeros((16,), dtype=np.uint16)

        # here 8 represents 1000, i.e., 1 • α^0 + 0 • α^1 + 0 • α^2 + 0 • α^3
        # => M[8]= M[1000] = 1 • H
        # Similarly, R[8] = R[1000] represents the remainder of 1 • H that needs to added
        self._M[8][:] = self.H[:]
        self._R[8] = self.R_poly

        i = 4
        # calculate,
        #   M[4]= M[0100] = H • α^1 = M[1000] • α^1
        #   M[2]= M[0010] = H • α^2 = M[0100] • α^1
        #   M[1]= M[0001] = H • α^3 = M[0010] • α^1
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

        # here 128 represents 10000000, i.e., 1 • α^0 + 0 • α^1 + 0 • α^2 + ... + 0 • α^7
        # => M[128]= M[10000000] = 1 • H
        # Similarly, R[128] = R[10000000] represents the remainder of 1 • H that needs to added
        self._M[128][:] = self.H[:]
        self._R[128] = self.R_poly

        i = 64
        # calculate,
        #   M[64]= M[01000000] = H • α^1 = M[10000000] • α^1
        #   M[32]= M[00100000] = H • α^2 = M[01000000] • α^1
        #   ...
        #   M[2]= M[00000010] = H • α^2 = M[00000100] • α^1
        #   M[1]= M[00000001] = H • α^3 = M[00000010] • α^1
        while i:
            self._R[i] = self._multiply_by_alpha(self._M[i], self._M[i << 1], self._R[i << 1],
                                                 bit_mask=0x0001, rem_mask=0xFFFF)
            i >>= 1

        i = 2
        # calculate,
        #   M[3] = M[00000011] = M[00000010] + M[00000001] = M[2] + M[1]
        #   M[5] = M[00000101] = M[00000100] + M[00000001] = M[4] + M[1]
        #   M[6] = M[00000110] = M[00000100] + M[00000010] = M[4] + M[2]
        #   M[7] = M[00000111] = M[00000100] + M[00000011] = M[4] + M[3]
        # ...
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

    def _multiply_using_shoup_4_bit_tables(self, x: np.ndarray):
        z = np.zeros((self._block_size,), dtype=np.uint8)

        for i in range(15, -1, -1):
            #
            # low nibble
            #

            # multiply by α^4
            a = self._shift_right_nibble(z)

            # reduce the above result based on the value of 'a'
            rem = self._R[a]
            # rem = self.R_4_bit[a]
            z[0] ^= rem >> 8
            z[1] ^= rem & 0xFF

            # Z ← Z ⊕ M[byte(X,i)]
            Bitwise.xor(z, self._M[x[i] & 0x0F], z)

            #
            # high nibble
            #

            # multiply by α^4
            a = self._shift_right_nibble(z)

            # reduce the above result based on the value of 'a'
            rem = self._R[a]
            # rem = self.R_4_bit[a]
            z[0] ^= rem >> 8
            z[1] ^= rem & 0xFF

            # Z ← Z ⊕ M[byte(X,i)]
            Bitwise.xor(z, self._M[x[i] >> 4], z)

        x[:] = z[:]

    def _multiply_using_shoup_8_bit_tables(self, x: np.ndarray):
        z = np.zeros((self._block_size,), dtype=np.uint8)

        # Idea:
        # we want
        #   Z = (X[0] • H • α^0) + (X[1] • H • α^8) + (X[2] • H • α^16) + ... + (X[15] • H • α^120)
        # where X[i] = x[0] • α^0 + x[1] • α^1 + x[2] • α^2 + ... + x[7] • α^7
        # that means, 'X' represents byte, 'x' represent bit

        # performed using below steps
        # 0) Z = 0
        # 1) Z = α^8 • Z = 0
        #    Z = M[X[15]] + Z = (X[15] • H) + 0 = (X[15] • H)
        # 2) Z = α^8 • Z = (X[15] • H • α^8)
        #    Z = M[X[14]] + Z = (X[14] • H) + (X[15] • H • α^8)
        # 3) Z = α^8 • Z = (X[14] • H • α^8) + (X[15] • H • α^16)
        #    Z = M[X[13]] + Z = (X[13] • H) + (X[14] • H • α^8) + (X[15] • H • α^16)
        # ...
        # 15) Z = α^8 • Z = (X[2] • H • α^8) + (X[3] • H • α^16) + ... + (X[15] • H • α^112)
        #     Z = M[X[1]] + Z = (X[1] • H) + (X[2] • H • α^8) + (X[3] • H • α^16) + ... + (X[15] • H • α^112)
        # 16) Z = α^8 • Z = (X[1] • H • α^8) + (X[2] • H • α^16) + ... + (X[15] • H • α^120)
        #     Z = M[X[0]] + Z = (X[0] • H) + (X[1] • H • α^8) + (X[2] • H • α^16) + ... + (X[15] • H • α^120)
        for i in range(15, -1, -1):
            # multiply by α^8
            a = self._shift_right_byte(z)

            # reduce the above result based on the value of 'a'
            rem = self._R[a]
            # rem = self.R_8_bit[a]
            z[0] ^= rem >> 8
            z[1] ^= rem & 0xFF

            # Z ← Z ⊕ M[byte(X,i)]
            Bitwise.xor(z, self._M[x[i]], z)

        x[:] = z[:]

    def _multiply_using_simple_4_bit_tables(self, x: np.ndarray):
        raise NotImplementedError('Yet to be implemented')

    def _multiply_using_simple_8_bit_tables(self, x: np.ndarray):
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
