import numpy as np

from typing import Optional, Union, Any, Tuple
from bitwise import Bitwise


class Rijndael:
    BLOCK_SIZE = 0

    def __init__(self, key: Optional[Union[str, np.ndarray]] = None, no_of_rounds: int = 0):
        self.key = key
        self.no_of_rounds = no_of_rounds

        self._key = None
        self._round_key = None
        if key is not None:
            self.set_key(key)

    def _validate_key(self):
        raise NotImplementedError('Provide the definition of validating key size function')

    def round_function(self, right: Any, key: Any) -> Any:
        raise NotImplementedError('Provide the definition of round function')

    def key_schedule(self):
        raise NotImplementedError('Provide the definition of key schedule')

    def get_round_key(self, round_no: int) -> Any:
        return self._round_key[round_no]

    def set_key(self, key: Union[str, np.ndarray]):
        self.key = key
        if isinstance(key, str):
            self._key = np.array(bytearray.fromhex(key))
        elif isinstance(key, np.ndarray):
            self._key = np.copy(key)
        else:
            raise ValueError('Invalid key data type')

        # validate the given key
        self._validate_key()

        # calculate round keys
        self.key_schedule()

    def encrypt(self, input_data: Union[str, np.ndarray]) -> Union[str, np.ndarray]:
        if isinstance(input_data, str):
            output_data = np.array(bytearray.fromhex(input_data))
        elif isinstance(input_data, np.ndarray):
            output_data = np.copy(input_data)
        else:
            raise ValueError('Invalid input')

        for i in range(self.no_of_rounds):
            _key = self.get_round_key(i)
            self.round_function(output_data, _key)

        if isinstance(input_data, str):
            output_data = bytes(output_data).hex().upper()

        return output_data

    def decrypt(self, input_data: Union[str, np.ndarray]) -> Union[str, np.ndarray]:
        if isinstance(input_data, str):
            output_data = np.array(bytearray.fromhex(input_data))
        elif isinstance(input_data, np.ndarray):
            output_data = np.copy(input_data)
        else:
            raise ValueError('Invalid input')

        for i in range(self.no_of_rounds, 0, -1):
            _key = self.get_round_key(i - 1)
            self.round_function(output_data, _key)

        if isinstance(input_data, str):
            output_data = bytes(output_data).hex().upper()

        return output_data
