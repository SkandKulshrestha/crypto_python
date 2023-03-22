import numpy as np

from enum import IntEnum
from typing import Optional, Union, Tuple
from utility import Utility
from bitwise import Bitwise
from feistel_cipher import FeistelCipher


class DesKeySize(IntEnum):
    DES_64_BIT_KEY = 8,
    DES_128_BIT_KEY = 16,
    DES_192_BIT_KEY = 24


class Des(FeistelCipher):
    BLOCK_SIZE = 8
    KEY_SHIFT = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
    S_BOXES = (
        # S1
        (
            (0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08, 0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07),
            (0x00, 0x0F, 0x07, 0x04, 0x0E, 0x02, 0x0D, 0x01, 0x0A, 0x06, 0x0C, 0x0B, 0x09, 0x05, 0x03, 0x08),
            (0x04, 0x01, 0x0E, 0x08, 0x0D, 0x06, 0x02, 0x0B, 0x0F, 0x0C, 0x09, 0x07, 0x03, 0x0A, 0x05, 0x00),
            (0x0F, 0x0C, 0x08, 0x02, 0x04, 0x09, 0x01, 0x07, 0x05, 0x0B, 0x03, 0x0E, 0x0A, 0x00, 0x06, 0x0D),
        ),

        # S2
        (
            (0x0F, 0x01, 0x08, 0x0E, 0x06, 0x0B, 0x03, 0x04, 0x09, 0x07, 0x02, 0x0D, 0x0C, 0x00, 0x05, 0x0A),
            (0x03, 0x0D, 0x04, 0x07, 0x0F, 0x02, 0x08, 0x0E, 0x0C, 0x00, 0x01, 0x0A, 0x06, 0x09, 0x0B, 0x05),
            (0x00, 0x0E, 0x07, 0x0B, 0x0A, 0x04, 0x0D, 0x01, 0x05, 0x08, 0x0C, 0x06, 0x09, 0x03, 0x02, 0x0F),
            (0x0D, 0x08, 0x0A, 0x01, 0x03, 0x0F, 0x04, 0x02, 0x0B, 0x06, 0x07, 0x0C, 0x00, 0x05, 0x0E, 0x09),
        ),

        # S3
        (
            (0x0A, 0x00, 0x09, 0x0E, 0x06, 0x03, 0x0F, 0x05, 0x01, 0x0D, 0x0C, 0x07, 0x0B, 0x04, 0x02, 0x08),
            (0x0D, 0x07, 0x00, 0x09, 0x03, 0x04, 0x06, 0x0A, 0x02, 0x08, 0x05, 0x0E, 0x0C, 0x0B, 0x0F, 0x01),
            (0x0D, 0x06, 0x04, 0x09, 0x08, 0x0F, 0x03, 0x00, 0x0B, 0x01, 0x02, 0x0C, 0x05, 0x0A, 0x0E, 0x07),
            (0x01, 0x0A, 0x0D, 0x00, 0x06, 0x09, 0x08, 0x07, 0x04, 0x0F, 0x0E, 0x03, 0x0B, 0x05, 0x02, 0x0C),
        ),

        # S4
        (
            (0x07, 0x0D, 0x0E, 0x03, 0x00, 0x06, 0x09, 0x0A, 0x01, 0x02, 0x08, 0x05, 0x0B, 0x0C, 0x04, 0x0F),
            (0x0D, 0x08, 0x0B, 0x05, 0x06, 0x0F, 0x00, 0x03, 0x04, 0x07, 0x02, 0x0C, 0x01, 0x0A, 0x0E, 0x09),
            (0x0A, 0x06, 0x09, 0x00, 0x0C, 0x0B, 0x07, 0x0D, 0x0F, 0x01, 0x03, 0x0E, 0x05, 0x02, 0x08, 0x04),
            (0x03, 0x0F, 0x00, 0x06, 0x0A, 0x01, 0x0D, 0x08, 0x09, 0x04, 0x05, 0x0B, 0x0C, 0x07, 0x02, 0x0E),
        ),

        # S5
        (
            (0x02, 0x0C, 0x04, 0x01, 0x07, 0x0A, 0x0B, 0x06, 0x08, 0x05, 0x03, 0x0F, 0x0D, 0x00, 0x0E, 0x09),
            (0x0E, 0x0B, 0x02, 0x0C, 0x04, 0x07, 0x0D, 0x01, 0x05, 0x00, 0x0F, 0x0A, 0x03, 0x09, 0x08, 0x06),
            (0x04, 0x02, 0x01, 0x0B, 0x0A, 0x0D, 0x07, 0x08, 0x0F, 0x09, 0x0C, 0x05, 0x06, 0x03, 0x00, 0x0E),
            (0x0B, 0x08, 0x0C, 0x07, 0x01, 0x0E, 0x02, 0x0D, 0x06, 0x0F, 0x00, 0x09, 0x0A, 0x04, 0x05, 0x03),
        ),

        # S6
        (
            (0x0C, 0x01, 0x0A, 0x0F, 0x09, 0x02, 0x06, 0x08, 0x00, 0x0D, 0x03, 0x04, 0x0E, 0x07, 0x05, 0x0B),
            (0x0A, 0x0F, 0x04, 0x02, 0x07, 0x0C, 0x09, 0x05, 0x06, 0x01, 0x0D, 0x0E, 0x00, 0x0B, 0x03, 0x08),
            (0x09, 0x0E, 0x0F, 0x05, 0x02, 0x08, 0x0C, 0x03, 0x07, 0x00, 0x04, 0x0A, 0x01, 0x0D, 0x0B, 0x06),
            (0x04, 0x03, 0x02, 0x0C, 0x09, 0x05, 0x0F, 0x0A, 0x0B, 0x0E, 0x01, 0x07, 0x06, 0x00, 0x08, 0x0D),
        ),

        # S7
        (
            (0x04, 0x0B, 0x02, 0x0E, 0x0F, 0x00, 0x08, 0x0D, 0x03, 0x0C, 0x09, 0x07, 0x05, 0x0A, 0x06, 0x01),
            (0x0D, 0x00, 0x0B, 0x07, 0x04, 0x09, 0x01, 0x0A, 0x0E, 0x03, 0x05, 0x0C, 0x02, 0x0F, 0x08, 0x06),
            (0x01, 0x04, 0x0B, 0x0D, 0x0C, 0x03, 0x07, 0x0E, 0x0A, 0x0F, 0x06, 0x08, 0x00, 0x05, 0x09, 0x02),
            (0x06, 0x0B, 0x0D, 0x08, 0x01, 0x04, 0x0A, 0x07, 0x09, 0x05, 0x00, 0x0F, 0x0E, 0x02, 0x03, 0x0C),
        ),

        # S8
        (
            (0x0D, 0x02, 0x08, 0x04, 0x06, 0x0F, 0x0B, 0x01, 0x0A, 0x09, 0x03, 0x0E, 0x05, 0x00, 0x0C, 0x07),
            (0x01, 0x0F, 0x0D, 0x08, 0x0A, 0x03, 0x07, 0x04, 0x0C, 0x05, 0x06, 0x0B, 0x00, 0x0E, 0x09, 0x02),
            (0x07, 0x0B, 0x04, 0x01, 0x09, 0x0C, 0x0E, 0x02, 0x00, 0x06, 0x0A, 0x0D, 0x0F, 0x03, 0x05, 0x08),
            (0x02, 0x01, 0x0E, 0x07, 0x04, 0x0A, 0x08, 0x0D, 0x0F, 0x0C, 0x09, 0x00, 0x03, 0x05, 0x06, 0x0B),
        )
    )

    def __init__(self, key: Optional[Union[str, np.ndarray]] = None):
        super(Des, self).__init__(key=key, no_of_rounds=16)

        self._working_buffer = np.zeros((self.BLOCK_SIZE,), dtype=np.uint8)

    def _validate_key(self):
        try:
            DesKeySize(len(self._key))
        except ValueError:
            raise ValueError(f'{len(self._key)} is not a valid key size')

    def _initial_permutation(self, buffer: np.ndarray):
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
        permute = (buffer[7] << 1) & 0x80
        permute |= buffer[6] & 0x40
        permute |= (buffer[5] >> 1) & 0x20
        permute |= (buffer[4] >> 2) & 0x10
        permute |= (buffer[3] >> 3) & 0x08
        permute |= (buffer[2] >> 4) & 0x04
        permute |= (buffer[1] >> 5) & 0x02
        permute |= (buffer[0] >> 6) & 0x01
        working_buffer[0] = permute

        # then 2nd byte,
        permute = (buffer[7] << 3) & 0x80
        permute |= (buffer[6] << 2) & 0x40
        permute |= (buffer[5] << 1) & 0x20
        permute |= buffer[4] & 0x10
        permute |= (buffer[3] >> 1) & 0x08
        permute |= (buffer[2] >> 2) & 0x04
        permute |= (buffer[1] >> 3) & 0x02
        permute |= (buffer[0] >> 4) & 0x01
        working_buffer[1] = permute

        # then 3rd byte,
        permute = (buffer[7] << 5) & 0x80
        permute |= (buffer[6] << 4) & 0x40
        permute |= (buffer[5] >> 3) & 0x20
        permute |= (buffer[4] << 2) & 0x10
        permute |= (buffer[3] << 1) & 0x08
        permute |= buffer[2] & 0x04
        permute |= (buffer[1] >> 1) & 0x02
        permute |= (buffer[0] >> 2) & 0x01
        working_buffer[2] = permute

        # then 4th byte,
        permute = (buffer[7] << 7) & 0x80
        permute |= (buffer[6] << 6) & 0x40
        permute |= (buffer[5] << 5) & 0x20
        permute |= (buffer[4] << 4) & 0x10
        permute |= (buffer[3] << 3) & 0x08
        permute |= (buffer[2] << 2) & 0x04
        permute |= (buffer[1] << 1) & 0x02
        permute |= buffer[0] & 0x01
        working_buffer[3] = permute

        # then 5th byte,
        permute = buffer[7] & 0x80
        permute |= (buffer[6] >> 1) & 0x40
        permute |= (buffer[5] >> 2) & 0x20
        permute |= (buffer[4] >> 3) & 0x10
        permute |= (buffer[3] >> 4) & 0x08
        permute |= (buffer[2] >> 5) & 0x04
        permute |= (buffer[1] >> 6) & 0x02
        permute |= (buffer[0] >> 7) & 0x01
        working_buffer[4] = permute

        # then 6th byte,
        permute = (buffer[7] << 2) & 0x80
        permute |= (buffer[6] << 1) & 0x40
        permute |= buffer[5] & 0x20
        permute |= (buffer[4] >> 1) & 0x10
        permute |= (buffer[3] >> 2) & 0x08
        permute |= (buffer[2] >> 3) & 0x04
        permute |= (buffer[1] >> 4) & 0x02
        permute |= (buffer[0] >> 5) & 0x01
        working_buffer[5] = permute

        # then 7th byte,
        permute = (buffer[7] << 4) & 0x80
        permute |= (buffer[6] << 3) & 0x40
        permute |= (buffer[5] << 2) & 0x20
        permute |= (buffer[4] << 1) & 0x10
        permute |= buffer[3] & 0x08
        permute |= (buffer[2] >> 1) & 0x04
        permute |= (buffer[1] >> 2) & 0x02
        permute |= (buffer[0] >> 3) & 0x01
        working_buffer[6] = permute

        # and the last, i.e., 8th byte
        permute = (buffer[7] << 6) & 0x80
        permute |= (buffer[6] << 5) & 0x40
        permute |= (buffer[5] << 4) & 0x20
        permute |= (buffer[4] << 3) & 0x10
        permute |= (buffer[3] << 2) & 0x08
        permute |= (buffer[2] << 1) & 0x04
        permute |= buffer[1] & 0x02
        permute |= (buffer[0] >> 1) & 0x01
        working_buffer[7] = permute

        # now take permute bytes back in input buffer
        buffer[:] = working_buffer[:]

    def _inverse_initial_permutation(self, buffer: np.ndarray):
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
        permute = (buffer[4] << 7) & 0x80
        permute |= (buffer[0] << 6) & 0x40
        permute |= (buffer[5] << 5) & 0x20
        permute |= (buffer[1] << 4) & 0x10
        permute |= (buffer[6] << 3) & 0x08
        permute |= (buffer[2] << 2) & 0x04
        permute |= (buffer[7] << 1) & 0x02
        permute |= buffer[3] & 0x01
        working_buffer[0] = permute

        # then 2nd byte,
        permute = (buffer[4] << 6) & 0x80
        permute |= (buffer[0] << 5) & 0x40
        permute |= (buffer[5] << 4) & 0x20
        permute |= (buffer[1] << 3) & 0x10
        permute |= (buffer[6] << 2) & 0x08
        permute |= (buffer[2] << 1) & 0x04
        permute |= buffer[7] & 0x02
        permute |= (buffer[3] >> 1) & 0x01
        working_buffer[1] = permute

        # then 3rd byte,
        permute = (buffer[4] << 5) & 0x80
        permute |= (buffer[0] << 4) & 0x40
        permute |= (buffer[5] << 3) & 0x20
        permute |= (buffer[1] << 2) & 0x10
        permute |= (buffer[6] << 1) & 0x08
        permute |= buffer[2] & 0x04
        permute |= (buffer[7] >> 1) & 0x02
        permute |= (buffer[3] >> 2) & 0x01
        working_buffer[2] = permute

        # then 4th byte,
        permute = (buffer[4] << 4) & 0x80
        permute |= (buffer[0] << 3) & 0x40
        permute |= (buffer[5] << 2) & 0x20
        permute |= (buffer[1] << 1) & 0x10
        permute |= buffer[6] & 0x08
        permute |= (buffer[2] >> 1) & 0x04
        permute |= (buffer[7] >> 2) & 0x02
        permute |= (buffer[3] >> 3) & 0x01
        working_buffer[3] = permute

        # then 5th byte,
        permute = (buffer[4] << 3) & 0x80
        permute |= (buffer[0] << 2) & 0x40
        permute |= (buffer[5] << 1) & 0x20
        permute |= buffer[1] & 0x10
        permute |= (buffer[6] >> 1) & 0x08
        permute |= (buffer[2] >> 2) & 0x04
        permute |= (buffer[7] >> 3) & 0x02
        permute |= (buffer[3] >> 4) & 0x01
        working_buffer[4] = permute

        # then 6th byte,
        permute = (buffer[4] << 2) & 0x80
        permute |= (buffer[0] << 1) & 0x40
        permute |= buffer[5] & 0x20
        permute |= (buffer[1] >> 1) & 0x10
        permute |= (buffer[6] >> 2) & 0x08
        permute |= (buffer[2] >> 3) & 0x04
        permute |= (buffer[7] >> 4) & 0x02
        permute |= (buffer[3] >> 5) & 0x01
        working_buffer[5] = permute

        # then 7th byte,
        permute = (buffer[4] << 1) & 0x80
        permute |= buffer[0] & 0x40
        permute |= (buffer[5] >> 1) & 0x20
        permute |= (buffer[1] >> 2) & 0x10
        permute |= (buffer[6] >> 3) & 0x08
        permute |= (buffer[2] >> 4) & 0x04
        permute |= (buffer[7] >> 5) & 0x02
        permute |= (buffer[3] >> 6) & 0x01
        working_buffer[6] = permute

        # and the last, i.e., 8th byte,
        permute = buffer[4] & 0x80
        permute |= (buffer[0] >> 1) & 0x40
        permute |= (buffer[5] >> 2) & 0x20
        permute |= (buffer[1] >> 3) & 0x10
        permute |= (buffer[6] >> 4) & 0x08
        permute |= (buffer[2] >> 5) & 0x04
        permute |= (buffer[7] >> 6) & 0x02
        permute |= (buffer[3] >> 7) & 0x01
        working_buffer[7] = permute

        # now take permute bytes back in input buffer
        buffer[:] = working_buffer[:]

    def _expansion(self, buffer: np.ndarray):
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
        permute = (buffer[3] << 5) & 0x20
        permute |= (buffer[0] >> 3) & 0x1F
        working_buffer[0] = permute

        # then 2nd byte,
        permute = (buffer[0] << 1) & 0x3E
        permute |= (buffer[1] >> 7) & 0x01
        working_buffer[1] = permute

        # then 3rd byte,
        permute = (buffer[0] << 5) & 0x20
        permute |= (buffer[1] >> 3) & 0x1F
        working_buffer[2] = permute

        # then 4th byte,
        permute = (buffer[1] << 1) & 0x3E
        permute |= (buffer[2] >> 7) & 0x01
        working_buffer[3] = permute

        # then 5th byte,
        permute = (buffer[1] << 5) & 0x20
        permute |= (buffer[2] >> 3) & 0x1F
        working_buffer[4] = permute

        # then 6th byte,
        permute = (buffer[2] << 1) & 0x3E
        permute |= (buffer[3] >> 7) & 0x01
        working_buffer[5] = permute

        # then 7th byte,
        permute = (buffer[2] << 5) & 0x20
        permute |= (buffer[3] >> 3) & 0x1F
        working_buffer[6] = permute

        # and the last, i.e., 8th byte,
        permute = (buffer[3] << 1) & 0x3E
        permute |= (buffer[0] >> 7) & 0x01
        working_buffer[7] = permute

        # now take permute bytes back in input buffer
        buffer[:] = working_buffer[:]

    def _substitution(self, buffer: np.ndarray):
        for i in range(self.BLOCK_SIZE):
            _s = self.S_BOXES[i]
            row = ((buffer[i] & 0x20) >> 4) | (buffer[i] & 0x01)
            col = (buffer[i] & 0x1E) >> 1
            buffer[i] = _s[row][col]

    def _permutation(self, buffer: np.ndarray):
        """
        Permutation shuffles the bits of a 32-bit half-block

        16	7	20	21	29	12	28	17
        1	15	23	26	5	18	31	10
        2	8	24	14	32	27	3	9
        19	13	30	6	22	11	4	25
        """
        working_buffer = self._working_buffer

        permute = (buffer[3] & 0x01) << 7
        permute |= (buffer[1] & 0x02) << 5
        permute |= (buffer[4] & 0x01) << 5
        permute |= (buffer[5] & 0x08) << 1
        permute |= buffer[7] & 0x08
        permute |= (buffer[2] & 0x01) << 2
        permute |= (buffer[6] & 0x01) << 1
        permute |= (buffer[4] & 0x08) >> 3
        working_buffer[0] = permute

        permute = (buffer[0] & 0x08) << 4
        permute |= (buffer[3] & 0x02) << 5
        permute |= (buffer[5] & 0x02) << 4
        permute |= (buffer[6] & 0x04) << 2
        permute |= buffer[1] & 0x08
        permute |= buffer[4] & 0x04
        permute |= buffer[7] & 0x02
        permute |= (buffer[2] & 0x04) >> 2
        working_buffer[1] = permute

        permute = (buffer[0] & 0x04) << 5
        permute |= (buffer[1] & 0x01) << 6
        permute |= (buffer[5] & 0x01) << 5
        permute |= (buffer[3] & 0x04) << 2
        permute |= (buffer[7] & 0x01) << 3
        permute |= (buffer[6] & 0x02) << 1
        permute |= buffer[0] & 0x02
        permute |= (buffer[2] & 0x08) >> 3
        working_buffer[2] = permute

        permute = (buffer[4] & 0x02) << 6
        permute |= (buffer[3] & 0x08) << 3
        permute |= (buffer[7] & 0x04) << 3
        permute |= (buffer[1] & 0x04) << 2
        permute |= (buffer[5] & 0x04) << 1
        permute |= (buffer[2] & 0x02) << 1
        permute |= (buffer[0] & 0x01) << 1
        permute |= (buffer[6] & 0x08) >> 3
        working_buffer[3] = permute

        working_buffer[4] = 0
        working_buffer[5] = 0
        working_buffer[6] = 0
        working_buffer[7] = 0

        # now take permute bytes back in input buffer
        buffer[:] = working_buffer[:]

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

    def _encrypt_one_block(self, data: np.ndarray):
        self._initial_permutation(data)
        super(Des, self).encrypt(data, output_data=data)
        self._inverse_initial_permutation(data)
        return data

    def _decrypt_one_block(self, data: np.ndarray):
        self._initial_permutation(data)
        super(Des, self).decrypt(data, output_data=data)
        self._inverse_initial_permutation(data)
        return data

    def split_lr(self, buffer: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        half = self.BLOCK_SIZE >> 1

        left = np.zeros((self.BLOCK_SIZE,), dtype=buffer.dtype)
        left[:half] = buffer[:half]

        buffer[:half] = buffer[half:]
        buffer[half:] = np.zeros((half,), dtype=buffer.dtype)

        return left, buffer

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

    def round_function(self, right: np.ndarray, key: np.ndarray):
        # expansion
        self._expansion(right)
        Bitwise.xor(right, key, out=right)
        self._substitution(right)
        self._permutation(right)

        return right

    def set_key(self, key: Union[str, np.ndarray]):
        super(Des, self).set_key(key)

    def encrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid plaintext')

        if len(output_data) % self.BLOCK_SIZE:
            raise ValueError(f'Input data is not multiple of block length ({self.BLOCK_SIZE} bytes)')

        no_of_blocks = len(output_data) // self.BLOCK_SIZE

        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self.BLOCK_SIZE
            output_data[_start: _end] = self._encrypt_one_block(output_data[_start: _end])

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data

    def decrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid ciphertext')

        if len(output_data) % self.BLOCK_SIZE:
            raise ValueError(f'Input data is not multiple of block length ({self.BLOCK_SIZE} bytes)')

        no_of_blocks = len(output_data) // self.BLOCK_SIZE

        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self.BLOCK_SIZE
            output_data[_start: _end] = self._decrypt_one_block(output_data[_start: _end])

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data


if __name__ == '__main__':
    # refer: https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/
    # des.htm#:~:text=DES%20works%20by%20encrypting%20groups,key%20size%20is%2056%20bits.
    _key = '133457799BBCDFF1'
    _input_data = '0123456789ABCDEF'
    print('Scenario 1')
    print(f'Key {_key}')
    print(f'Plaintext {_input_data}')
    des = Des()
    des.set_key(_key)
    _output_data = des.encrypt(_input_data)
    print(f'Ciphertext {_output_data}')
    if _output_data != '85E813540F0AB405':
        raise RuntimeError('Des encryption fails')

    _output_data = des.decrypt(_output_data)
    print(f'Plaintext {_output_data}')
    if _output_data != _input_data:
        raise RuntimeError('Des decryption fails')

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
    print('\nScenario 2')
    print(f'Key {_key}')
    print(f'Plaintext {_input_data}')
    des = Des()
    des.set_key(_key)
    _output_data = des.encrypt(_input_data)
    print(f'Ciphertext {_output_data}')
    if _output_data != 'C0B7A8D05F3A829C':
        raise RuntimeError('Des encryption fails')

    _output_data = des.decrypt(_output_data)
    print(f'Plaintext {_output_data}')
    if _output_data != _input_data:
        raise RuntimeError('Des decryption fails')
