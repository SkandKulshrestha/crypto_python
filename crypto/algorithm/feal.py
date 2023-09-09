# import external library
import numpy as np
import warnings

# from import external library
from abc import ABC
from enum import IntEnum
from typing import Optional, Union, Tuple

# from import internal library
from bitwise import Bitwise
from utility import Utility
from feistel_cipher import FeistelCipher
from symmetric import SymmetricModesOfOperation
from padding import PaddingScheme
from warning_crypto import WithdrawnWarning


class FEALKeySize(IntEnum):
    FEAL_64_BIT_KEY = 8


class FEALXKeySize(IntEnum):
    FEAL_128_BIT_KEY = 16


class FEAL(FeistelCipher, ABC):
    def __init__(
            self,
            key: Optional[Union[str, np.ndarray]] = None,
            iv: Optional[Union[str, np.ndarray]] = None,
            no_of_rounds: int = 4,
            key_parity: bool = True,
            mode: SymmetricModesOfOperation = SymmetricModesOfOperation.ECB,
            pad: PaddingScheme = PaddingScheme.M0):
        super(FEAL, self).__init__(
            key=key,
            iv=iv,
            no_of_rounds=no_of_rounds,
            block_size=8,
            mode=mode,
            pad=pad
        )

        # store key parity
        self.key_parity = key_parity

        # calculate number of subkey required
        self._no_of_subkey = no_of_rounds + 8

    def _validate_block_size(self):
        if self._block_size != 8:
            raise ValueError(f'{self._block_size} is not a valid block size')

    def _validate_key_size(self):
        try:
            FEALKeySize(len(self._key))

            # check key parity if enabled
            if self.key_parity:
                raise NotImplementedError

        except ValueError:
            raise ValueError(f'{len(self._key)} is not a valid key size')

    def _key_schedule(self):
        # calculate key size and initialize round key array
        self._key_size = len(self._key)
        self._round_key = np.zeros((self._no_of_subkey, 2), dtype=np.uint8)

        # create left and right array
        half = self._key_size >> 1
        left = np.zeros((half,), dtype=np.uint8)
        right = np.zeros((half,), dtype=np.uint8)

        left[:] = self._key[:half]
        right[:] = self._key[half:]

        # create backup array
        left_backup = np.zeros(left.shape, dtype=left.dtype)
        right_backup = Utility.copy_to_numpy(right)

        # compute and store each round key
        i = 0
        while i < self._no_of_subkey:
            # backup right array
            right_backup[:] = right[:]

            # perform xor between left_backup and right array,
            # and store the result in right array
            Bitwise.xor(left_backup, right, right)

            # backup left array
            left_backup[:] = left[:]
            self._fk(left, right)
            self._round_key[i, :] = left[:2]
            i += 1
            self._round_key[i, :] = left[2:]
            i += 1
            right[:] = left[:]
            left[:] = right_backup[:]

    def _split_lr(self, buffer: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        half = len(buffer) >> 1

        # create a left array of buffer size and copy left part of buffer
        left = np.zeros(buffer.shape, dtype=buffer.dtype)
        left[:half] = buffer[:half]

        # copy right part of buffer at the starting treating
        # as right array instead of creating new one
        buffer[:half] = buffer[half:]
        buffer[half:] = np.zeros((half,), dtype=buffer.dtype)

        return left, buffer

    def _merge_lr(self, left: np.ndarray, right: np.ndarray) -> np.ndarray:
        half = len(left) >> 1

        # copy data of right into left
        left[half:] = right[:half]

        return left

    def _round_function(self, buffer: np.ndarray, key: np.ndarray):
        pass

    @staticmethod
    def rot2(x: np.uint8) -> np.uint8:
        return np.uint8(x << 2 | x >> 6)

    def _s0(self, x1: np.uint8, x2: np.uint8) -> np.uint8:
        return self.rot2(x1 + x2)

    def _s1(self, x1: np.uint8, x2: np.uint8) -> np.uint8:
        return self.rot2(x1 + x2 + 1)

    def _fk(self, left: np.ndarray, right: np.ndarray):
        pass

    def _pre_processing(self, left: np.ndarray, right: np.ndarray, n: int):
        # Encryption:
        #       (L[0], R[0]) = (L[0], R[0]) ^ (K[N], K[N + 1], K[N + 2], K[N + 3])
        #       (L[0], R[0]) = (L[0], R[0]) ^ (0, L[0])
        # Decryption:
        #       (R[N], L[N]) = (R[N], L[N]) ^ (K[N + 4], K[N + 5], K[N + 6], K[N + 7])
        #       (R[N], L[N]) = (R[N], L[N]) ^ (0, R[N])
        left[0] ^= self._round_key[n][0]
        left[1] ^= self._round_key[n][1]

        n += 1
        left[2] ^= self._round_key[n][0]
        left[3] ^= self._round_key[n][1]

        n += 1
        right[0] ^= self._round_key[n][0]
        right[1] ^= self._round_key[n][1]

        n += 1
        right[2] ^= self._round_key[n][0]
        right[3] ^= self._round_key[n][1]

        Bitwise.xor(right, left, out=right)

    def _post_processing(self, left: np.ndarray, right: np.ndarray, n: int):
        # Encryption:
        #       (R[N], L[N]) = (R[N], L[N]) ^ (0, R[N])
        #       (R[N], L[N]) = (R[N], L[N]) ^ (K[N + 4], K[N + 5], K[N + 6], K[N + 7])
        # Decryption:
        #       (L[0], R[0]) = (L[0], R[0]) ^ (0, L[0])
        #       (L[0], R[0]) = (L[0], R[0]) ^ (K[N], K[N + 1], K[N + 2], K[N + 3])
        Bitwise.xor(left, right, out=left)

        right[0] ^= self._round_key[n][0]
        right[1] ^= self._round_key[n][1]

        n += 1
        right[2] ^= self._round_key[n][0]
        right[3] ^= self._round_key[n][1]

        n += 1
        left[0] ^= self._round_key[n][0]
        left[1] ^= self._round_key[n][1]

        n += 1
        left[2] ^= self._round_key[n][0]
        left[3] ^= self._round_key[n][1]

    def encrypt_one_block(self, buffer: np.ndarray) -> np.ndarray:
        # split the plaintext block into two equal pieces: (L[0], R[0])
        left, right = self._split_lr(buffer)
        temp = np.zeros(right.shape, dtype=right.dtype)

        # apply pre-processing on left and right
        self._pre_processing(left=left, right=right, n=self._no_of_rounds)

        # for each round i = 0, 1, ..., n; compute
        #   L[i+1] = R[i]
        #   R[i+1] = L[i] ^ F(R[i], K[i])
        # where F be the round function and K[i] be ith sub-key
        for i in range(self._no_of_rounds):
            temp[:] = right[:]
            _key = self.get_round_key(i)
            Bitwise.xor(left, self._round_function(right, _key), right)
            left[:] = temp[:]

        # apply post-processing on left and right
        self._post_processing(left=left, right=right, n=self._no_of_rounds + 4)

        # ciphertext is (R[n], L[n])
        buffer = self._merge_lr(left=right, right=left)

        return buffer

    def decrypt_one_block(self, buffer: np.ndarray) -> np.ndarray:
        # split the plaintext block into two equal pieces: (R[n], L[n])
        right, left = self._split_lr(buffer)
        temp = np.zeros(right.shape, dtype=right.dtype)

        # apply pre-processing on left and right
        self._pre_processing(left=right, right=left, n=self._no_of_rounds + 4)

        # for each round i = n, n-1, ..., 0; compute
        #   R[i] = L[i+1]
        #   L[i] = R[i+1] ^ F(L[i+1], K[i])
        # where F be the round function and K[i] be ith sub-key
        for i in range(self._no_of_rounds, 0, -1):
            temp[:] = left[:]
            _key = self.get_round_key(i - 1)
            Bitwise.xor(right, self._round_function(left, _key), left)
            right[:] = temp[:]

        # apply post-processing on left and right
        self._post_processing(left=right, right=left, n=self._no_of_rounds)

        # plaintext is (L[0], R[0])
        buffer = self._merge_lr(left=left, right=right)

        return buffer


class FEAL4(FEAL):
    def __init__(
            self,
            key: Optional[Union[str, np.ndarray]] = None,
            iv: Optional[Union[str, np.ndarray]] = None,
            mode: SymmetricModesOfOperation = SymmetricModesOfOperation.ECB,
            pad: PaddingScheme = PaddingScheme.M0):
        super(FEAL4, self).__init__(
            key=key,
            iv=iv,
            no_of_rounds=4,
            mode=mode,
            pad=pad
        )


class FEAL8(FEAL):
    def __init__(
            self,
            key: Optional[Union[str, np.ndarray]] = None,
            iv: Optional[Union[str, np.ndarray]] = None,
            mode: SymmetricModesOfOperation = SymmetricModesOfOperation.ECB,
            pad: PaddingScheme = PaddingScheme.M0):
        super(FEAL8, self).__init__(
            key=key,
            iv=iv,
            no_of_rounds=8,
            mode=mode,
            pad=pad
        )


class FEALn(FEAL):
    def __init__(
            self,
            key: Optional[Union[str, np.ndarray]] = None,
            iv: Optional[Union[str, np.ndarray]] = None,
            no_of_rounds: int = 0,
            mode: SymmetricModesOfOperation = SymmetricModesOfOperation.ECB,
            pad: PaddingScheme = PaddingScheme.M0):
        super(FEALn, self).__init__(
            key=key,
            iv=iv,
            no_of_rounds=no_of_rounds,
            mode=mode,
            pad=pad
        )


class FEALnx(FEAL):
    def __init__(
            self,
            key: Optional[Union[str, np.ndarray]] = None,
            iv: Optional[Union[str, np.ndarray]] = None,
            no_of_rounds: int = 0,
            mode: SymmetricModesOfOperation = SymmetricModesOfOperation.ECB,
            pad: PaddingScheme = PaddingScheme.M0):
        super(FEALnx, self).__init__(
            key=key,
            iv=iv,
            no_of_rounds=no_of_rounds,
            mode=mode,
            pad=pad
        )

    def _validate_key_size(self):
        try:
            FEALXKeySize(len(self._key))
        except ValueError:
            raise ValueError(f'{len(self._key)} is not a valid key size')
