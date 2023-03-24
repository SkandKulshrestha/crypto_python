from abc import ABC

import numpy as np

from enum import IntEnum
from symmetric import Symmetric
from typing import Optional, Union, Any
from utility import Utility
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
        0x00, 0x01, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
        0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6,
        0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5
    )
    _S_BOX = ()

    def __init__(self, key: Optional[Union[str, np.ndarray]] = None,
                 no_of_rounds: int = 0, block_size: int = 0):
        super(Rijndael, self).__init__(key=key, no_of_rounds=no_of_rounds, block_size=block_size)

        self._nb = self._block_size >> 2
        self._state_shape = (4, self._nb)
        self._working_buffer = np.zeros(self._state_shape, dtype=np.uint8)

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

    def _sub_byte(self, data: np.ndarray, out: np.ndarray) -> np.ndarray:
        for i in range(len(out)):
            out[i] = self._S_BOX[data[i]]
        return out

    @staticmethod
    def _rot_byte(data: np.ndarray, out: np.ndarray) -> np.ndarray:
        """
         cyclic permutation such that the input word (a,b,c,d) produces the output word (b,c,d,a)
        """
        out[:3] = data[1:]
        out[3] = data[0]
        return out

    @staticmethod
    def _convert_to_state(data: np.ndarray, out: np.ndarray = None):
        for i in range(4):
            out[i, :] = data[i::4]
        return out

    @staticmethod
    def _convert_from_state(data: np.ndarray, out: np.ndarray = None):
        for i in range(4):
            out[i, :] = data[i::4]
        return out

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
                state = self._S_BOX[state[i][j]]

    def _shift_rows(self, state: np.ndarray):
        for i in range(4):
            for j in range(self._nb):
                state = self._S_BOX[state[i][j]]

    def _mix_column(self, state: np.ndarray):
        for i in range(4):
            for j in range(self._nb):
                state = self._S_BOX[state[i][j]]

    @staticmethod
    def _add_round_key(state: np.ndarray, round_key: np.ndarray):
        Bitwise.xor(state, round_key, state)

    def _round_function(self, data: np.ndarray, round_key: np.ndarray) -> np.ndarray:
        self._byte_sub(state=data)
        self._shift_rows(state=data)
        self._mix_column(state=data)
        self._add_round_key(state=data, round_key=round_key)

    def _key_schedule(self):
        self._key_size = len(self._key)
        self._nk = self._key_size >> 2
        self._nr = self._NR_TABLE[(self._nk - 2) >> 1][(self._nb - 2) >> 1]
        self._no_of_rounds = self._nr
        self._round_key = np.zeros((self._no_of_rounds + 1, *self._state_shape), dtype=np.uint8)

        self._key_expansion()

    def encrypt_one_block(self, data: np.ndarray):
        state = np.zeros((4, self._nb), dtype=data.dtype)
        self._convert_to_state(data, out=state)

        self._add_round_key(state, self.get_round_key(0))

        for i in range(1, self._nr):
            self._round_function(state, self.get_round_key(i))

        self._final_round(state, self.get_round_key(self._nr))

        self._convert_from_state(state, out=data)
        return data

    def decrypt_one_block(self, data: np.ndarray):
        self._initial_permutation(data)
        super(Des, self).decrypt(data, output_data=data)
        self._inverse_initial_permutation(data)
        return data

    def encrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid plaintext')

        if len(output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes)')

        no_of_blocks = len(output_data) // self._block_size

        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self._block_size
            output_data[_start: _end] = self.encrypt_one_block(output_data[_start: _end])

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data

    def decrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid ciphertext')

        if len(output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes)')

        no_of_blocks = len(output_data) // self._block_size

        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self._block_size
            output_data[_start: _end] = self.decrypt_one_block(output_data[_start: _end])

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data
