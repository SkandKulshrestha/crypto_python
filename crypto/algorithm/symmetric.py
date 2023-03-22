import numpy as np

from typing import Optional, Union, Any
from utility import Utility


class Symmetric:
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
        raise NotImplementedError('Provide the definition of encrypt method')

    def decrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        raise NotImplementedError('Provide the definition of decrypt method')
