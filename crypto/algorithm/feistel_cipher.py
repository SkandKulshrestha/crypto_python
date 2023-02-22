import numpy as np

from typing import Optional, Union, Any, Tuple
from bitwise import Bitwise


class FeistelCipher:
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None, no_of_rounds: int = 0):
        self.key = key
        self.no_of_rounds = no_of_rounds

        self._key = None
        self._round_key = None
        if key is not None:
            self.set_key(key)

    def _validate_key(self):
        raise NotImplementedError('Provide the definition of validating key size function')

    def split_lr(self, input_data: np.ndarray) -> Tuple[Any, Any]:
        raise NotImplementedError('Provide the definition of function to split '
                                  'plaintext into left and right')

    def merge_lr(self, left: Any, right: Any) -> np.ndarray:
        raise NotImplementedError('Provide the definition of function to split '
                                  'plaintext into left and right')

    def round_function(self, right: Any, key: Any) -> Any:
        raise NotImplementedError('Provide the definition of no_of_rounds function')

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

        # split the plaintext block into two equal pieces: (L[0], R[0])
        left, right = self.split_lr(output_data)

        # for each round i = 0, 1, ..., n; compute
        #   L[i+1] = R[i]
        #   R[i+1] = L[i] ^ F(R[i], K[i])
        # where F be the round function and K[i] be ith sub-key
        for i in range(self.no_of_rounds):
            temp = right
            _key = self.get_round_key(i)
            right = Bitwise.xor(left, self.round_function(right, _key))
            left = temp

        # ciphertext is (R[n], L[n])
        output_data = self.merge_lr(left=right, right=left)

        if isinstance(input_data, str):
            output_data = bytes(output_data).hex()

        return output_data

    def decrypt(self, input_data: Union[str, np.ndarray]) -> Union[str, np.ndarray]:
        if isinstance(input_data, str):
            output_data = np.array(bytearray.fromhex(input_data))
        elif isinstance(input_data, np.ndarray):
            output_data = np.copy(input_data)
        else:
            raise ValueError('Invalid input')

        # split the plaintext block into two equal pieces: (R[n], L[n])
        right, left = self.split_lr(output_data)

        # for each round i = n, n-1, ..., 0; compute
        #   R[i] = L[i+1]
        #   L[i] = R[i+1] ^ F(L[i+1], K[i])
        # where F be the round function and K[i] be ith sub-key
        for i in range(self.no_of_rounds, 0, -1):
            temp = left
            _key = self.get_round_key(i-1)
            left = Bitwise.xor(right, self.round_function(left, _key))
            right = temp

        # plaintext is (L[0], R[0])
        output_data = self.merge_lr(left=left, right=right)

        if isinstance(input_data, str):
            output_data = bytes(output_data).hex()

        return output_data
