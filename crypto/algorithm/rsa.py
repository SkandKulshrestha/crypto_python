# import external library
import numpy as np

# from import external library
from enum import IntEnum
from typing import Any, Tuple, Union

# from import external library
from asymmetric import Asymmetric
from utility import Utility


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
    def __init__(self, n: str, e: str):
        self.n = int(n, 16)
        self.e = int(e, 16)

    def __repr__(self):
        return f'n : {self.get_n()}\n' \
               f'e : {self.get_e()}\n'

    def get_n(self) -> str:
        return Utility.convert_to_hex_string(self.n)

    def set_n(self, n: str):
        self.n = int(n, 16)

    def get_e(self) -> str:
        return Utility.convert_to_hex_string(self.e)

    def set_e(self, e: str):
        self.e = int(e, 16)


class RSAPrivateKey:
    def __init__(self, n: str, d: str):
        self.n = int(n, 16)
        self.d = int(d, 16)

    def __repr__(self):
        return f'n : {self.get_n()}\n' \
               f'd : {self.get_d()}\n'

    def get_n(self) -> str:
        return Utility.convert_to_hex_string(self.n)

    def set_n(self, n: str):
        self.n = int(n, 16)

    def get_d(self) -> str:
        return Utility.convert_to_hex_string(self.d)

    def set_d(self, d: str):
        self.d = int(d, 16)


class RSACRTPrivateKey:
    def __init__(self, p: str, q: str, dp: str, dq: str, q_inv: str):
        self.p = int(p, 16)
        self.q = int(q, 16)
        self.dp = int(dp, 16)
        self.dq = int(dq, 16)
        self.q_inv = int(q_inv, 16)

    def __repr__(self):
        return f'p : {self.get_p()}\n' \
               f'q : {self.get_q()}\n' \
               f'dp : {self.get_dp()}\n' \
               f'dq : {self.get_dq()}\n' \
               f'q_inv : {self.get_q_inv()}\n'

    def get_p(self) -> str:
        return Utility.convert_to_hex_string(self.p)

    def set_p(self, p: str):
        self.p = int(p, 16)

    def get_q(self) -> str:
        return Utility.convert_to_hex_string(self.q)

    def set_q(self, q: str):
        self.q = int(q, 16)

    def get_dp(self) -> str:
        return Utility.convert_to_hex_string(self.dp)

    def set_dp(self, dp: str):
        self.dp = int(dp, 16)

    def get_dq(self) -> str:
        return Utility.convert_to_hex_string(self.dq)

    def set_dq(self, dq: str):
        self.dq = int(dq, 16)

    def get_q_inv(self) -> str:
        return Utility.convert_to_hex_string(self.q_inv)

    def set_q_inv(self, q_inv: str):
        self.q_inv = int(q_inv, 16)


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
        print(f'p: {Utility.convert_to_hex_string(p)}')
        print(f'q: {Utility.convert_to_hex_string(q)}')

        # step 2: compute n = pq
        n = p * q

        # step 2: compute λ(n), where λ is Carmichael's totient function.
        # Since n = pq, λ(n) = lcm(λ(p), λ(q)), and since p and q are prime,
        # λ(p) = φ(p) = p − 1, and likewise λ(q) = q − 1. Hence λ(n) = lcm(p − 1, q − 1)
        #       lcm(a, b) = |ab| / gcd(a, b)
        p_minus_1 = p - 1
        q_minus_1 = q - 1
        lambda_n = (p_minus_1 * q_minus_1) // Utility.gcd(p_minus_1, q_minus_1)
        print(f'lambda_n: {Utility.convert_to_hex_string(lambda_n)}')

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
        self.public_key = RSAPublicKey(
            Utility.convert_to_hex_string(n),
            Utility.convert_to_hex_string(e)
        )

        # create an instance of private key
        self.private_key = RSAPrivateKey(
            Utility.convert_to_hex_string(n),
            Utility.convert_to_hex_string(d)
        )

        # create an instance of crt private key
        self.crt_private_key = RSACRTPrivateKey(
            Utility.convert_to_hex_string(p),
            Utility.convert_to_hex_string(q),
            Utility.convert_to_hex_string(dp),
            Utility.convert_to_hex_string(dq),
            Utility.convert_to_hex_string(q_inv)
        )

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

        return Utility.convert_to_hex_string(_c)

    def decrypt(self, input_data: Union[str, np.ndarray]) -> Union[str, np.ndarray]:
        if not isinstance(input_data, str):
            raise NotImplementedError('Only implemented to handle hex string')

        if self.private_key is None:
            raise ValueError('Private key not found')

        _c = int(input_data, 16)
        _m = Utility.modular_exponentiation(_c, self.private_key.d, self.private_key.n)

        return Utility.convert_to_hex_string(_m)

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

        return Utility.convert_to_hex_string(_m)

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
    print(pr_key)
    print(pu_key)

    c = rsa.encrypt('05')
    print(c)
    m = rsa.decrypt(c)
    print(m)
    m = rsa.decrypt_crt(c)
    print(m)

    # rsa = RSA(RSAModulus.RSA_MODULUS_1024)
    # pr_key, pu_key = rsa.generate_key_pair_from_p_and_q(
    #     p='aea082c57a5f9823a230b4a85d0b64733d8c079e46ca2dde3e18bf5deef5b0f7'
    #       '20d91b366e679edfed9f3d509e17963ebdd141d90e22a6a0f9ac6d9b47aad42b',
    #     q='e1a97a9ad69e1b85828e6e255daa61b33bb3d42cfdfbeaa0d4b28b1b4f5b6bd5'
    #       'a620be6d9bb1c1468fe0a5def57bcc438b7b944503901f7cd2a6ec61e919d6fb'
    # )
    # print(pr_key)
    # print(pu_key)
