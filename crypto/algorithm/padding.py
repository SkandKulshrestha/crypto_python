import numpy as np

from enum import IntEnum


class PaddingScheme(IntEnum):
    M0 = 0,
    M1 = 1,
    M2 = 2,
    M3 = 3,
    PKCS = 4


class Padding:
    def __init__(self, pad_scheme: PaddingScheme):
        self.pad_scheme = pad_scheme
        self.apply_padding = eval(f'self.apply_{pad_scheme.name.lower()}')
        self.remove_padding = eval(f'self.remove_{pad_scheme.name.lower()}')

    @staticmethod
    def apply_m0(data: np.ndarray) -> np.ndarray:
        return data

    @staticmethod
    def remove_m0(data: np.ndarray) -> np.ndarray:
        return data
