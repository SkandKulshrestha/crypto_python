# import external library
import numpy as np

# from import external library
from enum import IntEnum
from typing import Any, Tuple, Union

# from import internal library
from asymmetric import Asymmetric
from utility import Utility
from warning_crypto import InvalidComparison


class RSAModulus(IntEnum):
    RSA_MODULUS_32 = 4,
    RSA_MODULUS_64 = 8,
    RSA_MODULUS_128 = 16,
    RSA_MODULUS_256 = 32,
    RSA_MODULUS_512 = 64,
    RSA_MODULUS_1024 = 128,
    RSA_MODULUS_2048 = 256,
    RSA_MODULUS_4096 = 512


class RSAPublicKey:
    def __init__(self, n: Union[str, int], e: Union[str, int]):
        self.n = Utility.convert_to_int(n)
        self.e = Utility.convert_to_int(e)

    def __repr__(self):
        return f'n : 0x{self.get_n()}\n' \
               f'e : 0x{self.get_e()}\n'

    def __eq__(self, other):
        if isinstance(other, RSAPublicKey):
            return self.n == other.n and self.e == other.e
        raise InvalidComparison(self, other)

    def __ne__(self, other):
        return not (self == other)

    def get_n(self) -> str:
        return Utility.convert_int_to_hex_string(self.n)

    def set_n(self, n: str):
        self.n = Utility.convert_hex_string_to_int(n)

    def get_e(self) -> str:
        return Utility.convert_int_to_hex_string(self.e)

    def set_e(self, e: str):
        self.e = Utility.convert_hex_string_to_int(e)


class RSAPrivateKey:
    def __init__(self, n: Union[str, int], d: Union[str, int]):
        self.n = Utility.convert_to_int(n)
        self.d = Utility.convert_to_int(d)

    def __repr__(self):
        return f'n : 0x{self.get_n()}\n' \
               f'd : 0x{self.get_d()}\n'

    def __eq__(self, other):
        if isinstance(other, RSAPrivateKey):
            return self.n == other.n and self.d == other.d
        raise InvalidComparison(self, other)

    def __ne__(self, other):
        return not (self == other)

    def get_n(self) -> str:
        return Utility.convert_int_to_hex_string(self.n)

    def set_n(self, n: str):
        self.n = Utility.convert_hex_string_to_int(n)

    def get_d(self) -> str:
        return Utility.convert_int_to_hex_string(self.d)

    def set_d(self, d: str):
        self.d = Utility.convert_hex_string_to_int(d)


class RSACRTPrivateKey:
    def __init__(self, p: Union[str, int], q: Union[str, int],
                 dp: Union[str, int], dq: Union[str, int],
                 q_inv: Union[str, int]):
        self.p = Utility.convert_to_int(p)
        self.q = Utility.convert_to_int(q)
        self.dp = Utility.convert_to_int(dp)
        self.dq = Utility.convert_to_int(dq)
        self.q_inv = Utility.convert_to_int(q_inv)

    def __repr__(self):
        return f'p : 0x{self.get_p()}\n' \
               f'q : 0x{self.get_q()}\n' \
               f'dp : 0x{self.get_dp()}\n' \
               f'dq : 0x{self.get_dq()}\n' \
               f'q_inv : 0x{self.get_q_inv()}\n'

    def __eq__(self, other):
        if isinstance(other, RSACRTPrivateKey):
            return self.p == other.p and self.q == other.q and \
                   self.dp == other.dp and self.dq == other.dq and \
                   self.q_inv == other.q_inv
        raise InvalidComparison(self, other)

    def __ne__(self, other):
        return not (self == other)

    def get_p(self) -> str:
        return Utility.convert_int_to_hex_string(self.p)

    def set_p(self, p: str):
        self.p = Utility.convert_hex_string_to_int(p)

    def get_q(self) -> str:
        return Utility.convert_int_to_hex_string(self.q)

    def set_q(self, q: str):
        self.q = Utility.convert_hex_string_to_int(q)

    def get_dp(self) -> str:
        return Utility.convert_int_to_hex_string(self.dp)

    def set_dp(self, dp: str):
        self.dp = Utility.convert_hex_string_to_int(dp)

    def get_dq(self) -> str:
        return Utility.convert_int_to_hex_string(self.dq)

    def set_dq(self, dq: str):
        self.dq = Utility.convert_hex_string_to_int(dq)

    def get_q_inv(self) -> str:
        return Utility.convert_int_to_hex_string(self.q_inv)

    def set_q_inv(self, q_inv: str):
        self.q_inv = Utility.convert_hex_string_to_int(q_inv)


class RSA(Asymmetric):
    POSSIBLE_E = (3, 5, 17, 257, 65537)

    def __init__(self, modulus_length: int):
        super(RSA, self).__init__()
        self.crt_private_key = None

        self.modulus_length = modulus_length
        self.modulus_bit_length = modulus_length * 8

    def set_key_pair(self, private_key: Union[RSAPrivateKey, RSACRTPrivateKey], public_key: RSAPublicKey):
        if isinstance(private_key, RSAPrivateKey):
            self.private_key = private_key
        elif isinstance(private_key, RSACRTPrivateKey):
            self.crt_private_key = private_key
        else:
            raise ValueError('Private key must be an instance of "RSAPrivateKey"'
                             ' or "RSACRTPrivateKey"')

        if isinstance(public_key, RSAPublicKey):
            self.public_key = public_key
        else:
            raise ValueError('Public key must be an instance of "RSAPublicKey"')

    def _generate_key_pair_from_primes(self, p: int, q: int) -> Tuple[RSAPrivateKey, RSAPublicKey]:
        # print(f'p: 0x{Utility.convert_int_to_hex_string(p)}')
        # print(f'q: 0x{Utility.convert_int_to_hex_string(q)}')

        # step 2: compute n = pq
        n = p * q

        # step 3: compute λ(n), where λ is Carmichael's totient function.
        # Since n = pq, λ(n) = lcm(λ(p), λ(q)), and since p and q are prime,
        # λ(p) = φ(p) = p − 1, and likewise λ(q) = q − 1. Hence λ(n) = lcm(p − 1, q − 1)
        #       lcm(a, b) = |ab| / gcd(a, b)
        p_minus_1 = p - 1
        q_minus_1 = q - 1
        lambda_n = (p_minus_1 * q_minus_1) // Utility.gcd(p_minus_1, q_minus_1)
        # print(f'lambda_n: 0x{Utility.convert_int_to_hex_string(lambda_n)}')

        # step 4: choose an integer e such that 2 < e < λ(n) and gcd(e, λ(n)) = 1;
        # that is, e and λ(n) are co-prime
        for e in self.POSSIBLE_E:
            if Utility.gcd(e, lambda_n) == 1:
                break
        else:
            raise RuntimeError('Find different e')

        # step 5: determine d as ed ≡ 1 (mod λ(n));
        # that is, d is the modular multiplicative inverse of e modulo λ(n)
        d = Utility.inverse(e, lambda_n)

        _ed = e * d
        if Utility.modulus(_ed, lambda_n) != 1:
            raise RuntimeError('Does not hold, ed ≡ 1 (mod λ(n))')

        # compute crt private key
        dp = Utility.modulus(d, p_minus_1)
        dq = Utility.modulus(d, q_minus_1)
        q_inv = Utility.inverse(q, p)

        # create an instance of public key
        self.public_key = RSAPublicKey(n, e)

        # create an instance of private key
        self.private_key = RSAPrivateKey(n, d)

        # create an instance of crt private key
        self.crt_private_key = RSACRTPrivateKey(p, q, dp, dq, q_inv)

        return self.private_key, self.public_key

    def generate_key_pair(self) -> Tuple[RSAPrivateKey, RSAPublicKey]:
        prime_bit_length = self.modulus_bit_length // 2

        # step 1: choose two large prime numbers p and q
        p = Utility.generate_prime(prime_bit_length)
        q = Utility.generate_prime(prime_bit_length)

        return self._generate_key_pair_from_primes(p, q)

    def validate_key_pair(self, private_key: Union[RSAPrivateKey, RSACRTPrivateKey], public_key: RSAPublicKey) -> bool:
        raise NotImplementedError('Provide the definition of validate key pair method')

    def distribute_key(self) -> Any:
        raise NotImplementedError('Provide the definition of distribution key method')

    def encrypt(self, input_data: Union[str, np.ndarray]) -> Union[str, np.ndarray]:
        if not isinstance(input_data, str):
            raise NotImplementedError('Only implemented to handle hex string')

        if self.public_key is None:
            raise ValueError('Public key not found')

        _m = int(input_data, 16)
        _c = Utility.modular_exponentiation(_m, self.public_key.e, self.public_key.n)

        return Utility.convert_int_to_hex_string(_c)

    def decrypt(self, input_data: Union[str, np.ndarray]) -> Union[str, np.ndarray]:
        if not isinstance(input_data, str):
            raise NotImplementedError('Only implemented to handle hex string')

        if self.private_key is None:
            raise ValueError('Private key not found')

        _c = int(input_data, 16)
        _m = Utility.modular_exponentiation(_c, self.private_key.d, self.private_key.n)

        return Utility.convert_int_to_hex_string(_m)

    def decrypt_crt(self, input_data: Union[str, np.ndarray]) -> Union[str, np.ndarray]:
        if not isinstance(input_data, str):
            raise NotImplementedError('Only implemented to handle hex string')

        if self.crt_private_key is None:
            raise ValueError('CRT private key not found')

        _c = int(input_data, 16)
        _m1 = Utility.modular_exponentiation(_c, self.crt_private_key.dp, self.crt_private_key.p)
        _m2 = Utility.modular_exponentiation(_c, self.crt_private_key.dq, self.crt_private_key.q)
        _h = Utility.modulus(
            self.crt_private_key.q_inv * (_m1 - _m2),
            self.crt_private_key.p
        )
        _m = Utility.modulus(
            _m2 + (_h * self.crt_private_key.q),
            self.crt_private_key.p * self.crt_private_key.q
        )

        return Utility.convert_int_to_hex_string(_m)

    def generate_key_pair_from_p_and_q(self, p: str, q: str) -> Tuple[RSAPrivateKey, RSAPublicKey]:
        prime_bit_length = self.modulus_bit_length // 2

        # step 1: set prime p and q
        p = int(p, 16)
        q = int(q, 16)

        if Utility.get_bit_length(p) != prime_bit_length:
            raise ValueError(f'Prime p has {Utility.get_bit_length(p)} bit length but expecting {prime_bit_length} bit')

        if Utility.get_bit_length(q) != prime_bit_length:
            raise ValueError(f'Prime q has {Utility.get_bit_length(q)} bit length but expecting {prime_bit_length} bit')

        accuracy = 100
        if not Utility.is_prime(p, accuracy):
            raise ValueError('Parameter p is not probable prime')

        if not Utility.is_prime(q, accuracy):
            raise ValueError('Parameter q is not probable prime')

        return self._generate_key_pair_from_primes(p, q)

    def get_key_pair(self) -> Tuple[RSAPrivateKey, RSAPublicKey]:
        if self.private_key is None:
            raise ValueError('Private key is not set')
        if self.public_key is None:
            raise ValueError('Public key is not set')

        return self.private_key, self.public_key

    def get_crt_key_pair(self) -> Tuple[RSACRTPrivateKey, RSAPublicKey]:
        if self.crt_private_key is None:
            raise ValueError('CRT private key is not set')
        if self.public_key is None:
            raise ValueError('Public key is not set')

        return self.crt_private_key, self.public_key


if __name__ == '__main__':
    rsa = RSA(RSAModulus.RSA_MODULUS_1024)
    pr_key, pu_key = rsa.generate_key_pair()
    crt_key, _ = rsa.get_crt_key_pair()

    print(pr_key)
    print(crt_key)
    print(pu_key)

    m = '05'
    c = rsa.encrypt('05')
    m_decrypt = rsa.decrypt(c)
    m_decrypt_crt = rsa.decrypt_crt(c)
    print(f'Encryption of 0x{m} = 0x{c}')
    print(f'Decryption of 0x{c} = 0x{m_decrypt}')
    print(f'Decryption of 0x{c} using crt = 0x{m_decrypt_crt}')

    try:
        print(pu_key == pr_key)
    except InvalidComparison as _e:
        print(_e)

    try:
        print(crt_key == pr_key)
    except InvalidComparison as _e:
        print(_e)

    print('-' * 80)
    rsa = RSA(RSAModulus.RSA_MODULUS_1024)
    pr_key2, pu_key2 = rsa.generate_key_pair_from_p_and_q(
        p=crt_key.get_p(),
        q=crt_key.get_q()
    )
    print(pr_key2)
    print(pu_key2)

    print(f'{pr_key == pr_key2 = }')
    print(f'{pu_key == pu_key2 = }')

    print('-' * 80)
    rsa = RSA(RSAModulus.RSA_MODULUS_1024)
    pr_key3, pu_key3 = rsa.generate_key_pair()

    print(pr_key3)
    print(pu_key3)
    print(f'{pr_key == pr_key3 = }')
    print(f'{pu_key == pu_key3 = }')
