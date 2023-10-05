# import external library
import numpy as np

# from import external library
from abc import ABC
from typing import Optional, Union

# from import internal library
from utility import Utility


class Symmetric(ABC):
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None, no_of_rounds: int = 0, block_size: int = 0):
        # store key
        self.key = key

        # store block size and number of rounds
        self._block_size = block_size
        self._no_of_rounds = no_of_rounds

        # initialize key size, key (numpy array), and iv (numpy array)
        self._key_size = 0
        self._key = None

        # initialize round key (numpy array)
        self._round_key = None

        # validate block size
        self._validate_block_size()

        # set key (numpy array) if passed
        if key is not None:
            self.set_key(key)

    def _validate_block_size(self):
        raise NotImplementedError('Provide the definition of validate block size method')

    def _validate_key_size(self):
        raise NotImplementedError('Provide the definition of validate key size method')

    def _key_schedule(self):
        raise NotImplementedError('Provide the definition of key schedule method')

    def get_round_key(self, round_no: int) -> np.ndarray:
        if self._round_key is None:
            raise ValueError('Key is not set')

        if round_no > self._no_of_rounds:
            raise ValueError(f'Algorithm supports {self._no_of_rounds} rounds')

        return self._round_key[round_no]

    def set_key(self, key: Union[str, np.ndarray]):
        # store key
        self.key = key

        # store key as numpy array
        self._key = Utility.copy_to_numpy(key, error_msg='Invalid key')

        # validate key size
        self._validate_key_size()

        # calculate and store round keys
        self._key_schedule()

    def _encrypt(self, buffer: np.ndarray) -> np.ndarray:
        raise NotImplementedError('Provide the definition of encrypt method')

    def _decrypt(self, buffer: np.ndarray) -> np.ndarray:
        raise NotImplementedError('Provide the definition of decrypt method')

    def encrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        # copy input to output for further calculation
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid plaintext')

        if len(output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes).')

        # calculate number of complete blocks
        no_of_blocks = len(output_data) // self._block_size

        # process each block
        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self._block_size
            output_data[_start: _end] = self._encrypt(output_data[_start: _end])

        # return output in same format as input
        if isinstance(input_data, str):
            return Utility.convert_to_str(output_data)

        return output_data

    def decrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        # copy input to output for further calculation
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid ciphertext')

        if len(output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes)')

        # calculate number of complete blocks
        no_of_blocks = len(output_data) // self._block_size

        # process each block
        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self._block_size
            output_data[_start: _end] = self._decrypt(output_data[_start: _end])

        # return output in same format as input
        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data

    def get_block_size(self) -> int:
        return self._block_size

    def get_encrypt(self):
        return self._encrypt

    def get_decrypt(self):
        return self._decrypt


if __name__ == '__main__':
    try:
        Symmetric()
    except NotImplementedError:
        print('Symmetric interface cannot be instantiate')
