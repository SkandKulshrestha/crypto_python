from abc import ABC

import numpy as np

from symmetric import Symmetric
from typing import Optional, Union, Any
from utility import Utility


class Rijndael(Symmetric, ABC):
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None, no_of_rounds: int = 0):
        super(Rijndael, self).__init__(key=key, no_of_rounds=no_of_rounds)

    def round_function(self, data: Any, key: Any) -> Any:
        raise NotImplementedError('Provide the definition of round function')

    def key_schedule(self):
        raise NotImplementedError('Provide the definition of key schedule')

    def get_round_key(self, round_no: int) -> Any:
        return self._round_key[round_no]

    def set_key(self, key: Union[str, np.ndarray]):
        self.key = key
        self._key = Utility.copy_to_numpy(key, error_msg='Invalid key')

        # validate the given key
        self._validate_key()

        # calculate round keys
        self.key_schedule()

    def encrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid plaintext')

        for i in range(self.no_of_rounds):
            _key = self.get_round_key(i)
            self.round_function(output_data, _key)

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data

    def decrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid ciphertext')

        for i in range(self.no_of_rounds, 0, -1):
            _key = self.get_round_key(i - 1)
            self.round_function(output_data, _key)

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data
