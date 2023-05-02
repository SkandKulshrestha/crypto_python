import numpy as np

from enum import IntEnum
from symmetric import Symmetric
from typing import Optional, Union
from bitwise import Bitwise


class RijndaelKeySize(IntEnum):
    RIJNDAEL_128_BIT_KEY = 16,
    RIJNDAEL_192_BIT_KEY = 24,
    RIJNDAEL_256_BIT_KEY = 32


class RijndaelBlockSize(IntEnum):
    RIJNDAEL_128_BIT_BLOCK = 16,
    RIJNDAEL_192_BIT_BLOCK = 24,
    RIJNDAEL_256_BIT_BLOCK = 32


class Rijndael(Symmetric):
    _NR_TABLE = (
        (10, 12, 14),
        (12, 12, 14),
        (14, 14, 14)
    )
    # rc[i] is an eight-bit value defined as
    #         { 1                       if i = 1
    # rc[i] = { 2 * rc[i-1]             if i > 1 and rc[i-1] < 0x80
    #         { (2 * rc[i-1]) ^ 0x011B  if i > 1 and rc[i-1] >= 0x80
    _R_C = (
        0x00, 0x01, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F,
        0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5
    )
    _S_BOX = (
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    )
    _INVERSE_S_BOX = (
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    )
    _SHIFT_OFFSET = (
        (1, 2, 3),
        (1, 2, 3),
        (1, 3, 4),
    )
    _X_TIME = (
        0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
        0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
        0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
        0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
        0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
        0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
        0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
        0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
        0x1B, 0x19, 0x1F, 0x1D, 0x13, 0x11, 0x17, 0x15, 0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05,
        0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 0x2B, 0x29, 0x2F, 0x2D, 0x23, 0x21, 0x27, 0x25,
        0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55, 0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45,
        0x7B, 0x79, 0x7F, 0x7D, 0x73, 0x71, 0x77, 0x75, 0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65,
        0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 0x8B, 0x89, 0x8F, 0x8D, 0x83, 0x81, 0x87, 0x85,
        0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5, 0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5,
        0xDB, 0xD9, 0xDF, 0xDD, 0xD3, 0xD1, 0xD7, 0xD5, 0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5,
        0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 0xEB, 0xE9, 0xEF, 0xED, 0xE3, 0xE1, 0xE7, 0xE5
    )

    def __init__(self, key: Optional[Union[str, np.ndarray]] = None,
                 no_of_rounds: int = 0, block_size: int = 0):
        super(Rijndael, self).__init__(key=key, no_of_rounds=no_of_rounds, block_size=block_size)

        self._nb = self._block_size >> 2
        self._state_shape = (4, self._nb)
        self._working_buffer = np.zeros(self._state_shape, dtype=np.uint8)
        self._working_buffer2 = np.zeros((self._nb,), dtype=np.uint8)

    def _validate_block_size(self):
        try:
            RijndaelBlockSize(self._block_size)
        except ValueError:
            raise ValueError(f'{self._block_size} is not a valid block size')

    def _validate_key_size(self):
        try:
            RijndaelKeySize(len(self._key))
        except ValueError:
            raise ValueError(f'{len(self._key)} is not a valid key size')

    def _key_schedule(self):
        self._key_size = len(self._key)
        self._nk = self._key_size >> 2
        self._nr = self._NR_TABLE[(self._nk - 2) >> 1][(self._nb - 2) >> 1]
        self._no_of_rounds = self._nr
        self._round_key = np.zeros((self._no_of_rounds + 1, *self._state_shape), dtype=np.uint8)

        self._key_expansion()

    def _sub_byte(self, buffer: np.ndarray, out: np.ndarray) -> np.ndarray:
        for i in range(len(out)):
            out[i] = self._S_BOX[buffer[i]]
        return out

    @staticmethod
    def _rot_byte(buffer: np.ndarray, out: np.ndarray) -> np.ndarray:
        """
         cyclic permutation such that the input word (a,b,c,d) produces the output word (b,c,d,a)
        """
        out[:3] = buffer[1:]
        out[3] = buffer[0]
        return out

    @staticmethod
    def _convert_to_state(buffer: np.ndarray, out: np.ndarray = None):
        for i in range(4):
            out[i, :] = buffer[i::4]

    @staticmethod
    def _convert_from_state(buffer: np.ndarray, out: np.ndarray = None):
        for i in range(4):
            out[i::4] = buffer[i, :]

    def _extract_round_key(self, index: int, buffer: np.ndarray):
        for i in range(len(buffer)):
            self._round_key[index][i][0] = (buffer[i] >> 24) & 0xFF
            self._round_key[index][i][1] = (buffer[i] >> 16) & 0xFF
            self._round_key[index][i][2] = (buffer[i] >> 8) & 0xFF
            self._round_key[index][i][3] = buffer[i] & 0xFF

    def _key_expansion(self):
        key = np.zeros((4, len(self._key) >> 2), dtype=self._key.dtype)
        self._convert_to_state(self._key, out=key)
        max_range = self._nb * (self._nr + 1)
        working_buffer = np.zeros((max_range, 4), dtype=np.uint8)
        temp = np.zeros((4,), dtype=np.uint8)

        for i in range(max_range):
            if i < self._nk:
                working_buffer[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | \
                                    (key[4 * i + 2] << 8) | (key[4 * i + 3])

            elif i >= self._nk > 6 and i % self._nk == 4:
                self._sub_byte(working_buffer[i - 1], temp)
                Bitwise.xor(working_buffer[i - self._nk], temp, working_buffer[i])

            elif i >= self._nk and i % self._nk == 0:
                self._sub_byte(self._rot_byte(working_buffer[i - 1], temp), temp)
                # The round constant rcon[i] for round i of the key expansion is the 32-bit word
                # rcon[i] = [rc[i] 0x00 0x00 0x00]
                temp[0] ^= self._R_C[i // self._nk]
                Bitwise.xor(working_buffer[i - self._nk], temp, working_buffer[i])

            else:
                Bitwise.xor(working_buffer[i - self._nk], working_buffer[i - 1], working_buffer[i])

            if i % self._nk == 0:
                self._extract_round_key(i % self._nk, working_buffer[i - self._nk:i])

    def _byte_sub(self, state: np.ndarray):
        for i in range(4):
            for j in range(self._nb):
                state[i][j] = self._S_BOX[state[i][j]]

    def _shift_row(self, state: np.ndarray):
        temp = self._working_buffer2
        row = (self._nb >> 1) - 2

        for i in range(1, 4):
            shift = self._SHIFT_OFFSET[row][i - 1]
            temp[:] = state[i][:]
            state[i][0:self._nb - shift] = state[1][shift:self._nb]
            state[i][self._nb - shift:self._nb] = temp[0:shift]

    def _mix_column(self, state: np.ndarray):
        for i in range(4):
            for j in range(self._nb):
                state[i][j] = self._X_TIME[state[i][j]]
        raise NotImplementedError

    def _inv_byte_sub(self, state: np.ndarray):
        for i in range(4):
            for j in range(self._nb):
                state[i][j] = self._INVERSE_S_BOX[state[i][j]]

    def _inv_shift_row(self, state: np.ndarray):
        temp = self._working_buffer2
        row = (self._nb >> 1) - 2

        for i in range(1, 4):
            shift = self._SHIFT_OFFSET[row][i - 1]
            temp[:] = state[i][:]
            state[i][0:shift] = state[1][self._nb - shift:self._nb]
            state[i][shift:self._nb] = temp[0:self._nb - shift]

    def _inv_mix_column(self, state: np.ndarray):
        raise NotImplementedError

    @staticmethod
    def _add_round_key(state: np.ndarray, round_key: np.ndarray):
        Bitwise.xor(state, round_key, state)

    def encrypt_one_block(self, buffer: np.ndarray):
        state = np.zeros(self._state_shape, dtype=buffer.dtype)
        self._convert_to_state(buffer, out=state)

        self._add_round_key(state, self.get_round_key(0))

        for i in range(1, self._nr):
            self._byte_sub(state=state)
            self._shift_row(state=state)
            self._mix_column(state=state)
            self._add_round_key(state=state, round_key=self.get_round_key(i))

        self._byte_sub(state=state)
        self._shift_row(state=state)
        self._add_round_key(state=state, round_key=self.get_round_key(self._nr))

        self._convert_from_state(state, out=buffer)
        return buffer

    def decrypt_one_block(self, buffer: np.ndarray):
        state = np.zeros(self._state_shape, dtype=buffer.dtype)
        self._convert_to_state(buffer, out=state)

        self._add_round_key(state, self.get_round_key(self._nr))

        for i in range(self._nr - 1, 0, -1):
            self._inv_byte_sub(state=state)
            self._inv_shift_row(state=state)
            self._inv_mix_column(state=state)
            self._add_round_key(state=state, round_key=self.get_round_key(i))

        self._inv_byte_sub(state=state)
        self._inv_shift_row(state=state)
        self._add_round_key(state=state, round_key=self.get_round_key(0))

        self._convert_from_state(state, out=buffer)
        return buffer
