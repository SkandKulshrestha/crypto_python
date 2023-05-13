import numpy as np
import warnings

from enum import IntEnum
from feistel_cipher import FeistelCipher
from abc import ABC
from typing import Optional, Union, Tuple
from warning_crypto import WithdrawnWarning, KeyParityWarning


class FEALKeySize(IntEnum):
    FEAL_64_BIT_KEY = 8


class FEAL(FeistelCipher, ABC):
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None,
                 iv: Optional[Union[str, np.ndarray]] = None,
                 no_of_rounds: int = 0):
        super(FEAL, self).__init__(key=key, iv=iv, no_of_rounds=no_of_rounds, block_size=8)

    def _validate_block_size(self):
        if self._block_size != 8:
            raise ValueError(f'{self._block_size} is not a valid block size')

    def _validate_key_size(self):
        try:
            FEALKeySize(len(self._key))
        except ValueError:
            raise ValueError(f'{len(self._key)} is not a valid key size')

    def _key_schedule(self):
        pass

    def _split_lr(self, buffer: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        left = np.zeros((8, ))
        return left, buffer

    def _merge_lr(self, left: np.ndarray, right: np.ndarray) -> np.ndarray:
        return left

    def _round_function(self, buffer: np.ndarray, key: np.ndarray):
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