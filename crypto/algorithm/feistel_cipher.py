import numpy as np

from typing import Optional, Union


class FeistelCipher:
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None, no_of_rounds: int = 0):
        self.key = key
        self.no_of_rounds = no_of_rounds

        self._key = None
        self._round_key = None
        if key is not None:
            self.set_key(key)

    def _check_key_size(self):
        raise NotImplementedError('Provide the definition of validating key size function')

    def split_lr(self, input_data: np.ndarray):
        raise NotImplementedError('Provide the definition of function to split '
                                  'plaintext into left and right')

    def merge_lr(self, left: np.ndarray, right: np.ndarray):
        raise NotImplementedError('Provide the definition of function to split '
                                  'plaintext into left and right')

    def round_function(self, right: np.ndarray, key: np.ndarray):
        raise NotImplementedError('Provide the definition of no_of_rounds function')

    def key_schedule(self):
        raise NotImplementedError('Provide the definition of key schedule')

    def get_round_key(self, round_no: int):
        return self._round_key[round_no]

    def set_key(self, key: Union[str, np.ndarray]):
        self.key = key
        if isinstance(key, str):
            self._key = np.array(bytearray.fromhex(key))
        elif isinstance(key, np.ndarray):
            self._key = np.copy(key)
        else:
            raise ValueError('Invalid key data type')

        self._check_key_size()

        # calculate no_of_rounds keys
        self.key_schedule()

    def encrypt(self, input_data: Union[str, np.ndarray]):
        if isinstance(input_data, str):
            output_data = np.array(bytearray.fromhex(input_data))
        elif isinstance(input_data, np.ndarray):
            output_data = np.copy(input_data)
        else:
            raise ValueError('Invalid input')

        left, right = self.split_lr(output_data)
        for i in range(self.no_of_rounds):
            temp = np.copy(right)
            _key = self.get_round_key(i)
            right = np.bitwise_xor(left, self.round_function(right, _key))
            left = temp
        return self.merge_lr(left=right, right=left)
