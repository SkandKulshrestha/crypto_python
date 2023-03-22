from abc import ABC

import numpy as np

from symmetric import Symmetric
from typing import Optional, Union, Any, Tuple
from utility import Utility
from bitwise import Bitwise


class FeistelCipher(Symmetric, ABC):
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None, no_of_rounds: int = 0):
        super(FeistelCipher, self).__init__(key=key, no_of_rounds=no_of_rounds)

    def split_lr(self, buffer: np.ndarray) -> Tuple[Any, Any]:
        raise NotImplementedError('Provide the definition of function to split the buffer into left and right')

    def merge_lr(self, left: Any, right: Any) -> np.ndarray:
        raise NotImplementedError('Provide the definition of function to merge left and right')

    def encrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid plaintext')

        # split the plaintext block into two equal pieces: (L[0], R[0])
        left, right = self.split_lr(output_data)
        temp = np.zeros(right.shape, dtype=right.dtype)

        # for each round i = 0, 1, ..., n; compute
        #   L[i+1] = R[i]
        #   R[i+1] = L[i] ^ F(R[i], K[i])
        # where F be the round function and K[i] be ith sub-key
        for i in range(self.no_of_rounds):
            temp[:] = right[:]
            _key = self.get_round_key(i)
            Bitwise.xor(left, self.round_function(right, _key), right)
            left[:] = temp[:]

        # ciphertext is (R[n], L[n])
        output_data = self.merge_lr(left=right, right=left)

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data

    def decrypt(self, input_data: Union[str, np.ndarray], output_data: np.ndarray = None) -> Union[str, np.ndarray]:
        output_data = Utility.copy_to_numpy(input_data, out_data=output_data, error_msg='Invalid ciphertext')

        # split the plaintext block into two equal pieces: (R[n], L[n])
        right, left = self.split_lr(output_data)
        temp = np.zeros(right.shape, dtype=right.dtype)

        # for each round i = n, n-1, ..., 0; compute
        #   R[i] = L[i+1]
        #   L[i] = R[i+1] ^ F(L[i+1], K[i])
        # where F be the round function and K[i] be ith sub-key
        for i in range(self.no_of_rounds, 0, -1):
            temp[:] = left[:]
            _key = self.get_round_key(i - 1)
            Bitwise.xor(right, self.round_function(left, _key), left)
            right[:] = temp[:]

        # plaintext is (L[0], R[0])
        output_data = self.merge_lr(left=left, right=right)

        if isinstance(input_data, str):
            output_data = Utility.convert_to_str(output_data)

        return output_data
