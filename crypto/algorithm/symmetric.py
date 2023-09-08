# import external library
import numpy as np

# from import external library
from abc import ABC
from enum import IntEnum
from typing import Optional, Union, Any

# from import internal library
from utility import Utility
from padding import Padding, PaddingScheme


class SymmetricModesOfOperation(IntEnum):
    # Electronic codebook
    ECB = 0,
    # Cipher block chaining
    CBC = 1,
    # Propagating CBC
    PCBC = 2,
    # Output feedback
    OFB = 3,
    # Cipher feedback
    CFB = 4,
    # Counter
    CTR = 5


class Symmetric(ABC):
    def __init__(
            self,
            key: Optional[Union[str, np.ndarray]] = None,
            iv: Optional[Union[str, np.ndarray]] = None,
            no_of_rounds: int = 0,
            block_size: int = 0,
            mode: SymmetricModesOfOperation = SymmetricModesOfOperation.ECB,
            pad: PaddingScheme = PaddingScheme.M0):
        # store key and iv
        self.key = key
        self.iv = iv

        # store block size and number of rounds
        self._block_size = block_size
        self._no_of_rounds = no_of_rounds
        self.mode = mode
        self.pad = pad

        # initialize key size, key (numpy array), and iv (numpy array)
        self._key_size = 0
        self._key = None
        self._iv = None

        # initialize round key (numpy array)
        self._round_key = None

        # validate block size
        self._validate_block_size()

        # set key (numpy array) if passed
        if key is not None:
            self.set_key(key)

        # set iv (numpy array) if passed
        if iv is not None:
            self.set_iv(iv)

        if mode != SymmetricModesOfOperation.ECB:
            raise NotImplementedError('Yet to be implemented. Coming soon...')

        if pad != PaddingScheme.M0:
            raise NotImplementedError('Yet to be implemented. Coming soon...')

        self.padding = Padding(pad)

    def _validate_block_size(self):
        raise NotImplementedError('Provide the definition of validate block size method')

    def _validate_key_size(self):
        raise NotImplementedError('Provide the definition of validate key size method')

    def _key_schedule(self):
        raise NotImplementedError('Provide the definition of key schedule method')

    def get_round_key(self, round_no: int) -> Any:
        if self._round_key is None:
            raise ValueError('Key is not set')

        if round_no >= self._no_of_rounds:
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

    def set_iv(self, iv: Union[str, np.ndarray]):
        # store iv
        self.iv = iv

        # store iv as numpy array
        self._iv = Utility.copy_to_numpy(iv, error_msg='Invalid Initialization Vector')

        # validate iv length
        if self._block_size != len(self._iv):
            raise ValueError(f'{self._iv} is not a valid block size')

    def encrypt_one_block(self, buffer: np.ndarray) -> np.ndarray:
        raise NotImplementedError('Provide the definition of encrypt method for one block')

    def decrypt_one_block(self, buffer: np.ndarray) -> np.ndarray:
        raise NotImplementedError('Provide the definition of encrypt method for one block')

    def encrypt(
            self,
            input_data: Union[str, np.ndarray],
            output_data: np.ndarray = None,
            final: bool = False) -> Union[str, np.ndarray]:

        # copy input to output for further calculation
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid plaintext')

        # append padding in final call
        if final:
            output_data = self.padding.apply_padding(output_data)

        if len(output_data) % self._block_size:
            raise ValueError(f'Input data is not multiple of block length ({self._block_size} bytes).'
                             'Padding will only be handled in final call')

        # calculate number of complete blocks
        no_of_blocks = len(output_data) // self._block_size

        # process each block
        for i in range(no_of_blocks):
            _start = i * no_of_blocks
            _end = _start + self._block_size
            output_data[_start: _end] = self.encrypt_one_block(output_data[_start: _end])

        # return output in same format as input
        if isinstance(input_data, str):
            return Utility.convert_to_str(output_data)

        return output_data

    def decrypt(
            self,
            input_data: Union[str, np.ndarray],
            output_data: np.ndarray = None,
            final: bool = False) -> Union[str, np.ndarray]:
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
            output_data[_start: _end] = self.decrypt_one_block(output_data[_start: _end])

        # remove padding in final call
        if final:
            output_data = self.padding.remove_padding(output_data)

        # return output in same format as input
        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data


if __name__ == '__main__':
    try:
        Symmetric()
    except NotImplementedError:
        print('Symmetric interface cannot be instantiate')
