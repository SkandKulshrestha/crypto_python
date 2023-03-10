import numpy as np

from enum import IntEnum
from typing import Optional, Union, Tuple
from feistel_cipher import FeistelCipher


class DesKeySize(IntEnum):
    ONE_KEY = 8,
    TWO_KEY = 16,
    THREE_KEY = 24


class Des(FeistelCipher):
    # TODO: Better approach would be to compute calculation on 32/64 bits value directly
    # instead of array:
    # Work to do:
    # 2023/02/23: change the functionality, verify _permutation_choice1
    BLOCK_SIZE = 8
    KEY_SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

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
        input_data = working_buffer

        return input_data

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
        input_data = working_buffer

        return input_data

    def _expansion(self, input_data: np.ndarray):
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
        input_data = working_buffer

        return input_data

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
        left = np.uint32(0)
        right = np.uint32(0)

        # left
        left |= (key[7]) & 0x80
        left |= (key[6] >> 2) & 0x40
        left |= (key[5] >> 3) & 0x20
        left |= (key[4] >> 4) & 0x10
        left |= (key[3] >> 5) & 0x08
        left |= (key[2] >> 6) & 0x04
        left |= (key[1] >> 7) & 0x02

        left |= key[0] & 0x80
        left |= key[7] & 0x40
        left |= (key[6] >> 1) & 0x20
        left |= (key[5] >> 2) & 0x10
        left |= (key[4] >> 3) & 0x08
        left |= (key[3] >> 4) & 0x04
        left |= (key[2] >> 5) & 0x02

        left |= (key[1] << 1) & 0x80
        left |= key[0] & 0x40
        left |= key[7] & 0x20
        left |= (key[6] >> 1) & 0x10
        left |= (key[5] >> 2) & 0x08
        left |= (key[4] >> 3) & 0x04
        left |= (key[3] >> 4) & 0x02

        left |= (key[2] << 2) & 0x80
        left |= (key[1] << 1) & 0x40
        left |= key[0] & 0x20
        left |= key[7] & 0x10
        left |= (key[6] >> 1) & 0x08
        left |= (key[5] >> 2) & 0x04
        left |= (key[4] >> 3) & 0x02

        # right
        right |= (key[7] << 6) & 0x80
        right |= (key[6] << 5) & 0x40
        right |= (key[5] << 4) & 0x20
        right |= (key[4] << 3) & 0x10
        right |= (key[3] << 2) & 0x08
        right |= (key[2] << 1) & 0x04
        right |= key[1] & 0x02

        right |= (key[0] << 6) & 0x80
        right |= (key[7] << 5) & 0x40
        right |= (key[6] << 4) & 0x20
        right |= (key[5] << 3) & 0x10
        right |= (key[4] << 2) & 0x08
        right |= (key[3] << 1) & 0x04
        right |= key[2] & 0x02

        right |= (key[1] << 5) & 0x80
        right |= (key[0] << 4) & 0x40
        right |= (key[7] << 3) & 0x20
        right |= (key[6] << 2) & 0x10
        right |= (key[5] << 1) & 0x08
        right |= key[4] & 0x04
        right |= (key[3] >> 1) & 0x02

        right |= (key[2] << 4) & 0x80
        right |= (key[1] << 3) & 0x40
        right |= (key[0] << 2) & 0x20
        right |= (key[7] << 1) & 0x10
        right |= key[6] & 0x08
        right |= (key[5] >> 1) & 0x04
        right |= (key[4] >> 2) & 0x02

        return left, right

    def _permutation_choice2(self, left: np.ndarray, right: np.ndarray):
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
        return np.concatenate((left, right))

    @staticmethod
    def _right_rotate(key: np.ndarray, rotate_by: int):
        temp = key[3] & 0x01
        reverse_rotate_by = 8 - rotate_by
        mask = int('1' * rotate_by, 2)
        mask = mask << reverse_rotate_by
        key[3] = (key[3] >> rotate_by) | ((key[2] << reverse_rotate_by) & mask)
        key[2] = (key[2] >> rotate_by) | ((key[1] << reverse_rotate_by) & mask)
        key[1] = (key[1] >> rotate_by) | ((key[0] << reverse_rotate_by) & mask)
        key[0] = (key[0] >> rotate_by) | ((temp << reverse_rotate_by) & mask)
        return key

    def split_lr(self, input_data: np.ndarray) -> Tuple[np.uint32, np.uint32]:
        left = (input_data[0] << 24) | (input_data[1] << 16) | (input_data[2] << 8) | input_data[3]
        right = (input_data[4] << 24) | (input_data[5] << 16) | (input_data[6] << 8) | input_data[7]
        return left, right

    def merge_lr(self, left: np.uint32, right: np.uint32) -> np.ndarray:
        output_data = np.zeros((self.BLOCK_SIZE, ), dtype=np.uint8)
        output_data[0] = (left >> 24) & 0xFF
        output_data[1] = (left >> 16) & 0xFF
        output_data[2] = (left >> 8) & 0xFF
        output_data[3] = left & 0xFF
        output_data[4] = (right >> 24) & 0xFF
        output_data[5] = (right >> 16) & 0xFF
        output_data[6] = (right >> 8) & 0xFF
        output_data[7] = right & 0xFF
        return output_data

    def key_schedule(self):
        self._round_key = np.zeros((self.no_of_rounds, 2), dtype=np.uint32)

        left, right = self._permutation_choice1()
        for i in range(self.no_of_rounds):
            right = self._right_rotate(right, self.KEY_SHIFT[i])
            left = self._right_rotate(right, self.KEY_SHIFT[i])
            self._round_key[i] = self._permutation_choice2(left, right)

    def round_function(self, right: np.ndarray, key: np.ndarray):
        # expansion
        right = self._expansion(right)
        right = np.bitwise_xor(right, key)
        right = self._substitution(right)
        right = self._permutation(right)
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
            output_data[_start: _end] = self._initial_permutation(output_data[_start: _end])
            output_data[_start: _end] = super(Des, self).encrypt(output_data[_start: _end])
            output_data[_start: _end] = self._inverse_initial_permutation(output_data[_start: _end])

        return output_data


if __name__ == '__main__':
    # Plain Text: 123456ABCD132536
    # Key : AABB09182736CCDD
    #
    # Encryption
    #
    # After initial permutation: 14A7D67818CA18AD
    # After splitting: L0=14A7D678 R0=18CA18AD
    #
    # Round 1 18CA18AD 5A78E394 194CD072DE8C
    # Round 2 5A78E394 4A1210F6 4568581ABCCE
    # Round 3 4A1210F6 B8089591 06EDA4ACF5B5
    # Round 4 B8089591 236779C2 DA2D032B6EE3
    # Round 5 236779C2 A15A4B87 69A629FEC913
    # Round 6 A15A4B87 2E8F9C65 C1948E87475E
    # Round 7 2E8F9C65 A9FC20A3 708AD2DDB3C0
    # Round 8 A9FC20A3 308BEE97 34F822F0C66D
    # Round 9 308BEE97 10AF9D37 84BB4473DCCC
    # Round 10 10AF9D37 6CA6CB20 02765708B5BF
    # Round 11 6CA6CB20 FF3C485F 6D5560AF7CA5
    # Round 12 FF3C485F 22A5963B C2C1E96A4BF3
    # Round 13 22A5963B 387CCDAA 99C31397C91F
    # Round 14 387CCDAA BD2DD2AB 251B8BC717D0
    # Round 15 BD2DD2AB CF26B472 3330C5D9A36D
    # Round 16 19BA9212 CF26B472 181C5D75C66D
    #
    # Cipher Text: C0B7A8D05F3A829C
    #
    # Decryption
    #
    # After initial permutation: 19BA9212CF26B472
    # After splitting: L0=19BA9212 R0=CF26B472
    #
    # Round 1 CF26B472 BD2DD2AB 181C5D75C66D
    # Round 2 BD2DD2AB 387CCDAA 3330C5D9A36D
    # Round 3 387CCDAA 22A5963B 251B8BC717D0
    # Round 4 22A5963B FF3C485F 99C31397C91F
    # Round 5 FF3C485F 6CA6CB20 C2C1E96A4BF3
    # Round 6 6CA6CB20 10AF9D37 6D5560AF7CA5
    # Round 7 10AF9D37 308BEE97 02765708B5BF
    # Round 8 308BEE97 A9FC20A3 84BB4473DCCC
    # Round 9 A9FC20A3 2E8F9C65 34F822F0C66D
    # Round 10 2E8F9C65 A15A4B87 708AD2DDB3C0
    # Round 11 A15A4B87 236779C2 C1948E87475E
    # Round 12 236779C2 B8089591 69A629FEC913
    # Round 13 B8089591 4A1210F6 DA2D032B6EE3
    # Round 14 4A1210F6 5A78E394 06EDA4ACF5B5
    # Round 15 5A78E394 18CA18AD 4568581ABCCE
    # Round 16 14A7D678 18CA18AD 194CD072DE8C
    #
    # Plain Text: 123456ABCD132536
    _key = 'AABB09182736CCDD'
    _input_data = '123456ABCD132536'
    des = Des()
    des.set_key(_key)
    _output_data = des.encrypt(_input_data)
    print(_output_data)
    # if _output_data != 'C0B7A8D05F3A829C':
    #     raise RuntimeError('Des encryption fails')
