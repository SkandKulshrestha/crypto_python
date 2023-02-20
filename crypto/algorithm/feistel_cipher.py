import numpy as np

from typing import Optional, Union


class FeistelCipher:
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None):
        self.key = key
        self._key = None
        if key is not None:
            self.set_key(key)

    def round_function(self):
        pass

    def key_schedule(self):
        pass

    def set_key(self, key: Union[str, np.ndarray]):
        self.key = key
        if isinstance(key, str):
            self._key = np.array(bytearray.fromhex(key))
        elif isinstance(key, np.ndarray):
            self._key = np.copy(key)
        else:
            raise ValueError('Invalid key data type')

