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
        self.R = np.zeros((self._block_size,), dtype=np.uint8)
        self.R[0] = 0xE1

    def set_key(self, key: Union[str, np.ndarray]):
        self.algorithm.set_key(key)

        # allocate numpy buffer for H and iv
        self.H = np.zeros((self._block_size,), dtype=np.uint8)
        self._iv = np.zeros((self._block_size,), dtype=np.uint8)

        # compute H
        self.encrypt_one_block(self.H)

    @staticmethod
    def _shift_right(x: np.ndarray):
        bit = 0
        for i in range(len(x)):
            temp = (bit << 7) | (x[i] >> 1)
            bit = x[i] & 1
            x[i] = temp
        return bit

    def _multiply(self, x: np.ndarray, y: np.ndarray, out: np.ndarray):
        z = np.zeros((self._block_size,), dtype=np.uint8)
        v = y.copy()

        for i in range(127):
            j = i // 8
            m = 1 << (7 - (i & 7))

            if x[j] & m:
                Bitwise.xor(z, v, z)

            bit = self._shift_right(v)
            if bit:
                Bitwise.xor(v, self.R, v)

        out[:] = z[:]

    def _multiply_h(self, data: np.ndarray):
        self._multiply(data, self.H, data)

    @staticmethod
    def print_arr(arr):
        for i in range(len(arr)):
            print(f'{arr[i]:02X}', end=' ')
        print()

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

            print('GHASH')
            self.print_arr(self._iv)
            self.print_arr(output_data[_start: _end])
            self.print_arr(self.src_temp)
            Bitwise.xor(self._iv, output_data[_start: _end], self.src_temp)
            self.print_arr(self.src_temp)
            self._multiply_h(self.src_temp)
            self.print_arr(self.src_temp)
            self._iv[:] = self.src_temp[:]
            self.print_arr(self._iv)

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
