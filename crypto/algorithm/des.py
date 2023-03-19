import numpy as np

from enum import IntEnum
from typing import Optional, Union, Tuple
from feistel_cipher import FeistelCipher
from bitwise import Bitwise


class DesKeySize(IntEnum):
    ONE_KEY = 8,
    TWO_KEY = 16,
    THREE_KEY = 24


class Des(FeistelCipher):
    BLOCK_SIZE = 8
    KEY_SHIFT = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

    def __init__(self, key: Optional[Union[str, np.ndarray]] = None):
        super(Des, self).__init__(key=key, no_of_rounds=16)

        if self._key is not None:
            self._validate_key()

        self._working_buffer = np.zeros((self.BLOCK_SIZE,), dtype=np.uint8)

    def _validate_key(self):
        try:
            DesKeySize(len(self._key))
        except ValueError:
            raise ValueError(f'{len(self._key)} is not a valid key size')

    def _initial_permutation(self, input_data: np.ndarray):
        """
        Initial Permutation

        58    50    42    34    26    18    10    2
        60    52    44    36    28    20    12    4
        62    54    46    38    30    22    14    6
        64    56    48    40    32    24    16    8
        57    49    41    33    25    17     9    1
        59    51    43    35    27    19    11    3
        61    53    45    37    29    21    13    5
        63    55    47    39    31    23    15    7
        """
        working_buffer = self._working_buffer

        # compute 1st byte,
        permute = (input_data[7] << 1) & 0x80
        permute |= input_data[6] & 0x40
        permute |= (input_data[5] >> 1) & 0x20
        permute |= (input_data[4] >> 2) & 0x10
        permute |= (input_data[3] >> 3) & 0x08
        permute |= (input_data[2] >> 4) & 0x04
        permute |= (input_data[1] >> 5) & 0x02
        permute |= (input_data[0] >> 6) & 0x01
        working_buffer[0] = permute

        # then 2nd byte,
        permute = (input_data[7] << 3) & 0x80
        permute |= (input_data[6] << 2) & 0x40
        permute |= (input_data[5] << 1) & 0x20
        permute |= input_data[4] & 0x10
        permute |= (input_data[3] >> 1) & 0x08
        permute |= (input_data[2] >> 2) & 0x04
        permute |= (input_data[1] >> 3) & 0x02
        permute |= (input_data[0] >> 4) & 0x01
        working_buffer[1] = permute

        # then 3rd byte,
        permute = (input_data[7] << 5) & 0x80
        permute |= (input_data[6] << 4) & 0x40
        permute |= (input_data[5] >> 3) & 0x20
        permute |= (input_data[4] << 2) & 0x10
        permute |= (input_data[3] << 1) & 0x08
        permute |= input_data[2] & 0x04
        permute |= (input_data[1] >> 1) & 0x02
        permute |= (input_data[0] >> 2) & 0x01
        working_buffer[2] = permute

        # then 4th byte,
        permute = (input_data[7] << 7) & 0x80
        permute |= (input_data[6] << 6) & 0x40
        permute |= (input_data[5] << 5) & 0x20
        permute |= (input_data[4] << 4) & 0x10
        permute |= (input_data[3] << 3) & 0x08
        permute |= (input_data[2] << 2) & 0x04
        permute |= (input_data[1] << 1) & 0x02
        permute |= input_data[0] & 0x01
        working_buffer[3] = permute

        # then 5th byte,
        permute = input_data[7] & 0x80
        permute |= (input_data[6] >> 1) & 0x40
        permute |= (input_data[5] >> 2) & 0x20
        permute |= (input_data[4] >> 3) & 0x10
        permute |= (input_data[3] >> 4) & 0x08
        permute |= (input_data[2] >> 5) & 0x04
        permute |= (input_data[1] >> 6) & 0x02
        permute |= (input_data[0] >> 7) & 0x01
        working_buffer[4] = permute

        # then 6th byte,
        permute = (input_data[7] << 2) & 0x80
        permute |= (input_data[6] << 1) & 0x40
        permute |= input_data[5] & 0x20
        permute |= (input_data[4] >> 1) & 0x10
        permute |= (input_data[3] >> 2) & 0x08
        permute |= (input_data[2] >> 3) & 0x04
        permute |= (input_data[1] >> 4) & 0x02
        permute |= (input_data[0] >> 5) & 0x01
        working_buffer[5] = permute

        # then 7th byte,
        permute = (input_data[7] << 4) & 0x80
        permute |= (input_data[6] << 3) & 0x40
        permute |= (input_data[5] << 2) & 0x20
        permute |= (input_data[4] << 1) & 0x10
        permute |= input_data[3] & 0x08
        permute |= (input_data[2] >> 1) & 0x04
        permute |= (input_data[1] >> 2) & 0x02
        permute |= (input_data[0] >> 3) & 0x01
        working_buffer[6] = permute

        # and the last, i.e., 8th byte
        permute = (input_data[7] << 6) & 0x80
        permute |= (input_data[6] << 5) & 0x40
        permute |= (input_data[5] << 4) & 0x20
        permute |= (input_data[4] << 3) & 0x10
        permute |= (input_data[3] << 2) & 0x08
        permute |= (input_data[2] << 1) & 0x04
        permute |= input_data[1] & 0x02
        permute |= (input_data[0] >> 1) & 0x01
        working_buffer[7] = permute

        # now take permute bytes back in input buffer
        input_data[:] = working_buffer[:]

    def _inverse_initial_permutation(self, input_data: np.ndarray):
        """
        Inverse Initial Permutation

        40    8    48    16    56    24    64    32
        39    7    47    15    55    23    63    31
        38    6    46    14    54    22    62    30
        37    5    45    13    53    21    61    29
        36    4    44    12    52    20    60    28
        35    3    43    11    51    19    59    27
        34    2    42    10    50    18    58    26
        33    1    41     9    49    17    57    25
        """
        working_buffer = self._working_buffer

        # compute 1st byte,
        permute = (input_data[4] << 7) & 0x80
        permute |= (input_data[0] << 6) & 0x40
        permute |= (input_data[5] << 5) & 0x20
        permute |= (input_data[1] << 4) & 0x10
        permute |= (input_data[6] << 3) & 0x08
        permute |= (input_data[2] << 2) & 0x04
        permute |= (input_data[7] << 1) & 0x02
        permute |= input_data[3] & 0x01
        working_buffer[0] = permute

        # then 2nd byte,
        permute = (input_data[4] << 6) & 0x80
        permute |= (input_data[0] << 5) & 0x40
        permute |= (input_data[5] << 4) & 0x20
        permute |= (input_data[1] << 3) & 0x10
        permute |= (input_data[6] << 2) & 0x08
        permute |= (input_data[2] << 1) & 0x04
        permute |= input_data[7] & 0x02
        permute |= (input_data[3] >> 1) & 0x01
        working_buffer[1] = permute

        # then 3rd byte,
        permute = (input_data[4] << 5) & 0x80
        permute |= (input_data[0] << 4) & 0x40
        permute |= (input_data[5] << 3) & 0x20
        permute |= (input_data[1] << 2) & 0x10
        permute |= (input_data[6] << 1) & 0x08
        permute |= input_data[2] & 0x04
        permute |= (input_data[7] >> 1) & 0x02
        permute |= (input_data[3] >> 2) & 0x01
        working_buffer[2] = permute

        # then 4th byte,
        permute = (input_data[4] << 4) & 0x80
        permute |= (input_data[0] << 3) & 0x40
        permute |= (input_data[5] << 2) & 0x20
        permute |= (input_data[1] << 1) & 0x10
        permute |= input_data[6] & 0x08
        permute |= (input_data[2] >> 1) & 0x04
        permute |= (input_data[7] >> 2) & 0x02
        permute |= (input_data[3] >> 3) & 0x01
        working_buffer[3] = permute

        # then 5th byte,
        permute = (input_data[4] << 3) & 0x80
        permute |= (input_data[0] << 2) & 0x40
        permute |= (input_data[5] << 1) & 0x20
        permute |= input_data[1] & 0x10
        permute |= (input_data[6] >> 1) & 0x08
        permute |= (input_data[2] >> 2) & 0x04
        permute |= (input_data[7] >> 3) & 0x02
        permute |= (input_data[3] >> 4) & 0x01
        working_buffer[4] = permute

        # then 6th byte,
        permute = (input_data[4] << 2) & 0x80
        permute |= (input_data[0] << 1) & 0x40
        permute |= input_data[5] & 0x20
        permute |= (input_data[1] >> 1) & 0x10
        permute |= (input_data[6] >> 2) & 0x08
        permute |= (input_data[2] >> 3) & 0x04
        permute |= (input_data[7] >> 4) & 0x02
        permute |= (input_data[3] >> 5) & 0x01
        working_buffer[5] = permute

        # then 7th byte,
        permute = (input_data[4] << 1) & 0x80
        permute |= input_data[0] & 0x40
        permute |= (input_data[5] >> 1) & 0x20
        permute |= (input_data[1] >> 2) & 0x10
        permute |= (input_data[6] >> 3) & 0x08
        permute |= (input_data[2] >> 4) & 0x04
        permute |= (input_data[7] >> 5) & 0x02
        permute |= (input_data[3] >> 6) & 0x01
        working_buffer[6] = permute

        # and the last, i.e., 8th byte,
        permute = input_data[4] & 0x80
        permute |= (input_data[0] >> 1) & 0x40
        permute |= (input_data[5] >> 2) & 0x20
        permute |= (input_data[1] >> 3) & 0x10
        permute |= (input_data[6] >> 4) & 0x08
        permute |= (input_data[2] >> 5) & 0x04
        permute |= (input_data[7] >> 6) & 0x02
        permute |= (input_data[3] >> 7) & 0x01
        working_buffer[7] = permute

        # now take permute bytes back in input buffer
        input_data[:] = working_buffer[:]

    def _expansion(self, input_data: np.uint32) -> np.ndarray:
        """
        Expansion function

        32     1     2     3     4     5
         4     5     6     7     8     9
         8     9    10    11    12    13
        12    13    14    15    16    17
        16    17    18    19    20    21
        20    21    22    23    24    25
        24    25    26    27    28    29
        28    29    30    31    32     1
        """
        working_buffer = self._working_buffer

        # compute 1st byte,
        permute = (input_data[3] << 7) & 0x80
        permute |= (input_data[0] >> 1) & 0x7C
        working_buffer[0] = permute

        # then 2nd byte,
        permute = (input_data[0] << 3) & 0xF8
        permute |= (input_data[1] >> 5) & 0x04
        working_buffer[1] = permute

        # then 3rd byte,
        permute = (input_data[0] << 7) & 0x80
        permute |= (input_data[1] >> 1) & 0x7C
        working_buffer[2] = permute

        # then 4th byte,
        permute = (input_data[1] << 3) & 0xF8
        permute |= (input_data[2] >> 5) & 0x04
        working_buffer[3] = permute

        # then 5th byte,
        permute = (input_data[1] << 7) & 0x80
        permute |= (input_data[2] >> 1) & 0x7C
        working_buffer[4] = permute

        # then 6th byte,
        permute = (input_data[2] << 3) & 0xF8
        permute |= (input_data[3] >> 5) & 0x04
        working_buffer[5] = permute

        # then 7th byte,
        permute = (input_data[2] << 7) & 0x80
        permute |= (input_data[3] >> 1) & 0x7C
        working_buffer[6] = permute

        # and the last, i.e., 8th byte,
        permute = (input_data[3] << 3) & 0xF8
        permute |= (input_data[0] >> 5) & 0x04
        working_buffer[7] = permute

        # now take permute bytes back in input buffer
        input_data[:] = working_buffer[:]

    def _substitution(self, input_data: np.ndarray):
        working_buffer = self._working_buffer

        # now take permute bytes back in input buffer
        input_data = working_buffer[:4]

        return input_data

    def _permutation(self, input_data: np.ndarray):
        working_buffer = self._working_buffer

        # now take permute bytes back in input buffer
        input_data = working_buffer[:4]

        return input_data

    def _permutation_choice1(self) -> Tuple[np.uint32, np.uint32]:
        """
        Left
        57    49    41    33    25    17     9
         1    58    50    42    34    26    18
        10     2    59    51    43    35    27
        19    11     3    60    52    44    36
        Right
        63    55    47    39    31    23    15
         7    62    54    46    38    30    22
        14     6    61    53    45    37    29
        21    13     5    28    20    12     4
        """
        key = self._key
        left, right = 0, 0

        # left
        # first 8 bits
        for i in range(7, -1, -1):
            left |= (key[i] & 0x80) << (13 + i)

        # next 8 bits
        for i in range(7, -1, -1):
            left |= (key[i] & 0x40) << (6 + i)

        # next 7 bits
        for i in range(7, 0, -1):
            left |= (key[i] & 0x20) << (i - 1)

        # next 5 bits
        left |= (key[0] & 0x20) >> 1
        left |= (key[7] & 0x10) >> 1
        left |= (key[6] & 0x10) >> 2
        left |= (key[5] & 0x10) >> 3
        left |= (key[4] & 0x10) >> 4

        # right
        # first 8 bits
        for i in range(7, -1, -1):
            right |= (key[i] & 0x02) << (19 + i)

        # next 8 bits
        for i in range(7, -1, -1):
            right |= (key[i] & 0x04) << (10 + i)

        # next 8 bits
        for i in range(7, -1, -1):
            right |= (key[i] & 0x08) << (1 + i)

        # next 4 bits
        right |= (key[3] & 0x10) >> 1
        right |= (key[2] & 0x10) >> 2
        right |= (key[1] & 0x10) >> 3
        right |= (key[0] & 0x10) >> 4

        return np.uint32(left), np.uint32(right)

    def _permutation_choice2(self, left: np.uint32, right: np.uint32, round_no: int):
        """
        14    17    11    24     1     5
         3    28    15     6    21    10
        23    19    12     4    26     8
        16     7    27    20    13     2
        41    52    31    37    47    55
        30    40    51    45    33    48
        44    49    39    56    34    53
        46    42    50    36    29    32
        """
        # for fast access
        _round_key = self._round_key[round_no]

        result = (left & 0x00004000) >> 9
        result |= (left & 0x00000800) >> 7
        result |= (left & 0x00020000) >> 14
        result |= (left & 0x00000010) >> 2
        result |= (left & 0x08000000) >> 26
        result |= (left & 0x00800000) >> 23
        _round_key[0] = np.uint8(result)

        result = (left & 0x02000000) >> 20
        result |= (left & 0x00000001) << 4
        result |= (left & 0x00002000) >> 10
        result |= (left & 0x00400000) >> 20
        result |= (left & 0x00000080) >> 6
        result |= (left & 0x00040000) >> 18
        _round_key[1] = np.uint8(result)

        result = left & 0x00000020
        result |= (left & 0x00000200) >> 5
        result |= (left & 0x00010000) >> 13
        result |= (left & 0x01000000) >> 22
        result |= (left & 0x00000004) >> 1
        result |= (left & 0x00100000) >> 20
        _round_key[2] = np.uint8(result)

        result = (left & 0x00001000) >> 7
        result |= (left & 0x00200000) >> 17
        result |= (left & 0x00000002) << 2
        result |= (left & 0x00000100) >> 6
        result |= (left & 0x00008000) >> 14
        result |= (left & 0x04000000) >> 26
        _round_key[3] = np.uint8(result)

        result = (right & 0x00008000) >> 10
        result |= right & 0x00000010
        result |= (right & 0x02000000) >> 22
        result |= (right & 0x00080000) >> 17
        result |= (right & 0x00000200) >> 8
        result |= (right & 0x00000002) >> 1
        _round_key[4] = np.uint8(result)

        result = (right & 0x04000000) >> 21
        result |= (right & 0x00010000) >> 12
        result |= (right & 0x00000020) >> 2
        result |= (right & 0x00000800) >> 9
        result |= (right & 0x00800000) >> 22
        result |= (right & 0x00000100) >> 8
        _round_key[5] = np.uint8(result)

        result = (right & 0x00001000) >> 7
        result |= (right & 0x00000080) >> 3
        result |= (right & 0x00020000) >> 14
        result |= (right & 0x00000001) << 2
        result |= (right & 0x00400000) >> 21
        result |= (right & 0x00000008) >> 3
        _round_key[6] = np.uint8(result)

        result = (right & 0x00000400) >> 5
        result |= (right & 0x00004000) >> 10
        result |= (right & 0x00000040) >> 3
        result |= (right & 0x00100000) >> 18
        result |= (right & 0x08000000) >> 26
        result |= (right & 0x01000000) >> 24
        _round_key[7] = np.uint8(result)

    @staticmethod
    def _left_circular_rotate(key: np.uint32, rotate_by: int) -> np.uint32:
        while rotate_by:
            lsb = (key >> 27) & 0x01
            key = (key << 1) | lsb
            rotate_by -= 1
        key &= 0x0FFFFFFF
        return np.uint32(key)

    def split_lr(self, input_data: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        half = self.BLOCK_SIZE >> 1

        left = np.zeros(input_data.shape, dtype=input_data.dtype)
        left[:half] = input_data[:half]

        right = np.zeros(input_data.shape, dtype=input_data.dtype)
        right[:half] = input_data[half:]

        return left, right

    def merge_lr(self, left: np.ndarray, right: np.ndarray) -> np.ndarray:
        half = self.BLOCK_SIZE >> 1

        # copy data of right into left
        left[half:] = right[:half]

        return left

    def key_schedule(self):
        self._round_key = np.zeros((self.no_of_rounds, self.BLOCK_SIZE), dtype=np.uint8)

        left, right = self._permutation_choice1()
        for i in range(self.no_of_rounds):
            right = self._left_circular_rotate(right, self.KEY_SHIFT[i])
            left = self._left_circular_rotate(left, self.KEY_SHIFT[i])
            self._permutation_choice2(left, right, i)

    def round_function(self, right: np.uint32, key: np.ndarray):
        # expansion
        self._expansion(right)
        Bitwise.xor(right, key, out=right)
        self._substitution(right)
        self._permutation(right)

        return right

    def set_key(self, key: Union[str, np.ndarray]):
        super(Des, self).set_key(key)

    def encrypt(self, input_data: Union[str, np.ndarray]):
        if isinstance(input_data, str):
            output_data = np.array(bytearray.fromhex(input_data))
        elif isinstance(input_data, np.ndarray):
            output_data = np.copy(input_data)
        else:
            raise ValueError('Invalid input')

        if len(output_data) % self.BLOCK_SIZE:
            raise ValueError(f'Input data is not multiple of block length ({self.BLOCK_SIZE} bytes)')

        no_of_blocks = len(output_data) // self.BLOCK_SIZE

        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self.BLOCK_SIZE
            self._initial_permutation(output_data[_start: _end])
            output_data[_start: _end] = super(Des, self).encrypt(output_data[_start: _end])
            self._inverse_initial_permutation(output_data[_start: _end])

        return output_data


if __name__ == '__main__':
    # refer: https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/
    # des.htm#:~:text=DES%20works%20by%20encrypting%20groups,key%20size%20is%2056%20bits.
    _key = '133457799BBCDFF1'
    _input_data = '0123456789ABCDEF'
    des = Des()
    des.set_key(_key)
    _output_data = des.encrypt(_input_data)
    print(_output_data)
    # if _output_data != 'C0B7A8D05F3A829C':
    #     raise RuntimeError('Des encryption fails')
