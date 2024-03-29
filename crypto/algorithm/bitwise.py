# import external library
import numpy as np

# from import external library
from typing import Union, Tuple, List


class Bitwise:
    def __init__(self):
        pass

    @staticmethod
    def xor(a: Union[str, np.ndarray, int, Tuple, List],
            b: Union[str, np.ndarray, int, Tuple, List],
            out: Union[np.ndarray, List] = None) \
            -> Union[str, np.ndarray, int, Tuple, List]:

        if type(a) != type(b):
            raise ValueError(f'Cannot perform xor on different type {type(a)}, {type(b)}')

        if isinstance(a, int):
            return a ^ b
        elif isinstance(a, str):
            raise NotImplementedError('Yet to be implemented... Sorry for the inconvenience')
        elif isinstance(a, list):
            raise NotImplementedError('Yet to be implemented... Sorry for the inconvenience')
        elif isinstance(a, np.ndarray):
            return np.bitwise_xor(a, b, out=out)
