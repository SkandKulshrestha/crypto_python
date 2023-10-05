# import external library
import numpy as np

# from import external library
from abc import ABC
from typing import Optional, Union, Any, Tuple

# from import internal library
from symmetric import Symmetric
from bitwise import Bitwise


class FeistelCipher(Symmetric, ABC):
    def __init__(self, key: Optional[Union[str, np.ndarray]] = None, no_of_rounds: int = 0, block_size: int = 0):
        super(FeistelCipher, self).__init__(key=key, no_of_rounds=no_of_rounds, block_size=block_size)

    def _split_lr(self, buffer: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        raise NotImplementedError('Provide the definition of method to split the buffer into left and right')

    def _merge_lr(self, left: np.ndarray, right: Any) -> np.ndarray:
        raise NotImplementedError('Provide the definition of method to merge left and right')

    def _round_function(self, buffer: np.ndarray, round_key: np.ndarray) -> np.ndarray:
        raise NotImplementedError('Provide the definition of method to perform single round')

    def _encrypt(self, buffer: np.ndarray) -> np.ndarray:
        # split the plaintext block into two equal pieces: (L[0], R[0])
        left, right = self._split_lr(buffer)
        temp = np.zeros(right.shape, dtype=right.dtype)

        # for each round i = 0, 1, ..., n; compute
        #   L[i+1] = R[i]
        #   R[i+1] = L[i] ^ F(R[i], K[i])
        # where F be the round function and K[i] be ith sub-key
        for i in range(self._no_of_rounds):
            temp[:] = right[:]
            _key = self.get_round_key(i)
            Bitwise.xor(left, self._round_function(right, _key), right)
            left[:] = temp[:]

        # ciphertext is (R[n], L[n])
        buffer = self._merge_lr(left=right, right=left)

        return buffer

    def _decrypt(self, buffer: np.ndarray) -> np.ndarray:
        # split the plaintext block into two equal pieces: (R[n], L[n])
        right, left = self._split_lr(buffer)
        temp = np.zeros(right.shape, dtype=right.dtype)

        # for each round i = n, n-1, ..., 0; compute
        #   R[i] = L[i+1]
        #   L[i] = R[i+1] ^ F(L[i+1], K[i])
        # where F be the round function and K[i] be ith sub-key
        for i in range(self._no_of_rounds, 0, -1):
            temp[:] = left[:]
            _key = self.get_round_key(i - 1)
            Bitwise.xor(right, self._round_function(left, _key), left)
            right[:] = temp[:]

        # plaintext is (L[0], R[0])
        buffer = self._merge_lr(left=left, right=right)

        return buffer


if __name__ == '__main__':
    try:
        FeistelCipher()
    except NotImplementedError:
        print('FeistelCipher interface cannot be instantiate')
