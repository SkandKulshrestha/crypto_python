import numpy as np
import warnings

from enum import IntEnum
from algorithm.bitwise import Bitwise
from algorithm.utility import Utility
from feistel_cipher import FeistelCipher
from abc import ABC
from typing import Optional, Union, Tuple
from warning_crypto import WithdrawnWarning, KeyParityWarning


class FEALKeySize(IntEnum):
    FEAL_64_BIT_KEY = 8


class FEALXKeySize(IntEnum):
    FEAL_128_BIT_KEY = 16


class FEAL(FeistelCipher, ABC):
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None,
                 iv: Optional[Union[str, np.ndarray]] = None,
                 no_of_rounds: int = 4):
        super(FEAL, self).__init__(key=key, iv=iv, no_of_rounds=no_of_rounds, block_size=8)

        self._no_of_subkey = no_of_rounds + 8

    def _validate_block_size(self):
        if self._block_size != 8:
            raise ValueError(f'{self._block_size} is not a valid block size')

    def _validate_key_size(self):
        try:
            FEALKeySize(len(self._key))
        except ValueError:
            raise ValueError(f'{len(self._key)} is not a valid key size')

    def _key_schedule(self):
        self._key_size = len(self._key)
        self._round_key = np.zeros((self._no_of_subkey, 2), dtype=np.uint8)

        half = self._key_size >> 1
        left = np.zeros((half,), dtype=np.uint8)
        right = np.zeros((half,), dtype=np.uint8)

        left[:] = self._key[:half]
        right[:] = self._key[half:]

        left_backup = np.zeros(left.shape, dtype=left.dtype)
        right_backup = Utility.copy_to_numpy(right)

        i = 0
        while i < self._no_of_subkey:
            right_backup[:] = right[:]
            Bitwise.xor(left_backup, right, right)
            left_backup[:] = left[:]
            self._fk(left, right)
            self._round_key[i, :] = left[:2]
            i += 1
            self._round_key[i, :] = left[2:]
            i += 1
            right[:] = left[:]
            left[:] = right_backup[:]

    def _split_lr(self, buffer: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        half = len(buffer) >> 1

        left = np.zeros(buffer.shape, dtype=buffer.dtype)
        left[:half] = buffer[:half]

        buffer[:half] = buffer[half:]
        buffer[half:] = np.zeros((half,), dtype=buffer.dtype)

        return left, buffer

    def _merge_lr(self, left: np.ndarray, right: np.ndarray) -> np.ndarray:
        half = len(left) >> 1

        # copy data of right into left
        left[half:] = right[:half]

        return left

    def _round_function(self, buffer: np.ndarray, key: np.ndarray):
        pass

    def _fk(self, left: np.ndarray, right: np.ndarray):
        pass


class FEAL4(FEAL):
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None,
                 iv: Optional[Union[str, np.ndarray]] = None):
        super(FEAL4, self).__init__(key=key, iv=iv, no_of_rounds=4)


class FEAL8(FEAL):
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None,
                 iv: Optional[Union[str, np.ndarray]] = None):
        super(FEAL8, self).__init__(key=key, iv=iv, no_of_rounds=8)


class FEALn(FEAL):
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None,
                 iv: Optional[Union[str, np.ndarray]] = None,
                 no_of_rounds: int = 0):
        super(FEALn, self).__init__(key=key, iv=iv, no_of_rounds=no_of_rounds)


class FEALnx(FEAL):
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None,
                 iv: Optional[Union[str, np.ndarray]] = None,
                 no_of_rounds: int = 0):
        super(FEALnx, self).__init__(key=key, iv=iv, no_of_rounds=no_of_rounds)

    def _validate_key_size(self):
        try:
            FEALXKeySize(len(self._key))
        except ValueError:
            raise ValueError(f'{len(self._key)} is not a valid key size')
