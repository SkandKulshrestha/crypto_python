import sys
import numpy as np
import math

from typing import Union, Tuple


class Utility:
    @staticmethod
    def copy_to_numpy(data: Union[str, np.ndarray], out_data=None, error_msg: str = 'Invalid data'):
        if isinstance(data, str):
            _out_data = np.array(bytearray.fromhex(data))
        elif isinstance(data, np.ndarray):
            _out_data = np.copy(data)
        else:
            raise ValueError(f'{error_msg}. Only hex string and numpy array are supported')

        if out_data is None:
            out_data = _out_data
        else:
            out_data[:] = _out_data[:]

        return out_data

    @staticmethod
    def convert_to_str(data: np.ndarray) -> str:
        return bytes(data).hex().upper()

    @staticmethod
    def convert_to_hex_string(a: int) -> str:
        _a = hex(a)[2:]
        if len(_a) & 1:
            _a = f'0{_a}'
        return _a

    @staticmethod
    def generate_random(length: int) -> str:
        _rand = np.random.randint(low=0, high=256, size=length)
        _rand_list = [f'{r:02X}' for r in _rand]
        _rand_str = ''.join(_rand_list)
        return _rand_str.upper()

    @staticmethod
    def miller_rabin_wiki(n: int, k: int) -> bool:
        # let s > 0 and d odd > 0 such that n − 1 = 2sd  # by factoring out powers of 2 from n − 1
        n_minus_1 = n - 1
        s = 0
        while n_minus_1 & 1 == 0:
            s += 1
            n_minus_1 >>= 1
        d = n_minus_1
        n_minus_1 = n - 1

        length = len(Utility.convert_to_hex_string(n - 2)) // 2

        # repeat k times:
        while k:
            # a ← random(2, n − 2)  # n is always a probable prime to base 1 and n − 1
            if length == 1:
                a_length = 1
            else:
                a_length = np.random.randint(low=1, high=length, size=1)
            a = int(Utility.generate_random(a_length), 16)
            a = Utility.modulus(a, n_minus_1)
            if a < 2:
                continue

            # x ← pow(a,d) mod n
            x = Utility.modular_exponentiation(a, d, n)

            # no significance here, only to remove warning
            y = 2

            # repeat s times:
            while s:
                # y ← pow(x,2) mod n
                y = Utility.modular_exponentiation(x, 2, n)

                # if y = 1 and x ≠ 1 and x ≠ n − 1 then return “composite” # nontrivial square root of 1 modulo n
                if y == 1 and x != 1 and x != n_minus_1:
                    return False

                # x ← y
                x = y

                s -= 1

            # if y ≠ 1 then return “composite”
            if y != 1:
                return False

            k -= 1

        # return “probably prime”
        return True

    @staticmethod
    def miller_rabin(n: int, k: int) -> bool:
        # let s > 0 and d odd > 0 such that n − 1 = 2sd  # by factoring out powers of 2 from n − 1
        n_minus_1 = n - 1
        s = 0
        while n_minus_1 & 1 == 0:
            s += 1
            n_minus_1 >>= 1
        d = n_minus_1
        n_minus_1 = n - 1

        length = len(Utility.convert_to_hex_string(n - 2)) // 2

        # repeat k times:
        while k:
            # pick a random number 'a' in range [2, n-2]
            if length == 1:
                a_length = 1
            else:
                a_length = np.random.randint(low=1, high=length, size=1)
            a = int(Utility.generate_random(a_length), 16)
            a = 2 + Utility.modulus(a, n - 4)

            # compute: x = pow(a, d) % n
            x = Utility.modular_exponentiation(a, d, n)

            # if x == 1 or x == n-1, return true
            if x == 1 or x == n_minus_1:
                return True

            _d = d
            # repeat s times:
            while _d != n_minus_1:
                # x ← pow(x,2) mod n
                x = Utility.modular_exponentiation(x, 2, n)
                _d <<= 1

                if x == 1:
                    return False
                if x == n_minus_1:
                    return True

            k -= 1

        return False

    @staticmethod
    def is_prime(n: int, k: int) -> bool:
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n & 1 == 0:
            return False

        return Utility.miller_rabin(n, k)

    @staticmethod
    def generate_prime(prime_bit_length: int) -> int:
        attempt = 10000
        accuracy = 100
        prime_length = (prime_bit_length + 7) // 8
        print('Trying to generate a prime', end='')

        # Technique 1:
        prime_try = attempt

        while prime_try:
            if prime_try % 100 == 0:
                print('.', end='')
                sys.stdout.flush()

            # generate random number of given length
            prime = int(Utility.generate_random(prime_length), 16)

            # make it odd and prime_bit_length long
            prime |= (1 << (prime_bit_length - 1)) | 1

            # now, random ends in 1, 3, 5, 7, 9
            # eliminate ending with 5 as it is multiple of 5
            if prime % 5 == 0:
                prime += 2

            # check for probable prime
            if Utility.is_prime(prime, accuracy):
                print()
                print(f'Technique 1: Tries: {attempt - prime_try + 1}')
                return prime

            # decrease number of attempt
            prime_try -= 1
        else:
            raise RuntimeError('Unable to generate prime')

        # # Technique 2:
        # attempt = 10000000000
        # prime_try = attempt
        #
        # # generate random number of given length
        # prime = int(Utility.generate_random(prime_length), 16)
        #
        # # make it odd and prime_bit_length long
        # prime |= (1 << (prime_bit_length - 1)) | 1
        # # now, random ends in 1, 3, 5, 7, 9
        #
        # # make it multiple of 5
        # prime += 5 - Utility.modulus(prime, 5)
        #
        # # ends with 7
        # prime += 2
        #
        # # now, only check for ending with 1, 3, 7, 9
        # # so, increment in following order +2, +2, +2, +4
        # inc = (2, 2, 2, 4)
        # index = 0
        #
        # while prime_try:
        #     if prime_try % 100000000 == 0:
        #         print('.', end='')
        #         sys.stdout.flush()
        #
        #     # check for probable prime
        #     if Utility.is_prime(prime, accuracy):
        #         print()
        #         print(f'Technique 2: Tries: {attempt - prime_try + 1}')
        #         return prime
        #
        #     prime += inc[index]
        #     index = (index + 1) % 4
        #
        #     # decrease number of attempt
        #     prime_try -= 10

    @staticmethod
    def gcd(a: int, b: int) -> int:
        return math.gcd(a, b)

    @staticmethod
    def extended_euclidean_algorithm(a: int, b: int) -> Tuple[int, int, int]:
        # as + bt = gcd(a, b)

        # (old_r, r) := (a, b)
        old_r, r = a, b

        # (old_s, s) := (1, 0)
        old_s, s = 1, 0

        # (old_t, t) := (0, 1)
        old_t, t = 0, 1

        while r:
            # quotient := old_r div r
            quotient = old_r // r

            # (old_r, r) := (r, old_r − quotient × r)
            temp = r
            r = old_r - quotient * temp
            old_r = temp

            # (old_s, s) := (s, old_s − quotient × s)
            temp = s
            s = old_s - quotient * temp
            old_s = temp

            # (old_t, t) := (t, old_t − quotient × t)
            temp = t
            t = old_t - quotient * temp
            old_t = temp

        # "Bézout coefficients:", (old_s, old_t)
        # "greatest common divisor:", old_r
        # "quotients by the gcd:", (t, s)
        return s, t, old_r

    @staticmethod
    def inverse(a: int, n: int) -> int:
        # t := 0;     newt := 1
        t, new_t = 0, 1

        # r := n;     newr := a
        r, new_r = n, a

        while new_r:
            # quotient := r div newr
            quotient = r // new_r

            # (t, newt) := (newt, t − quotient × newt)
            temp = new_t
            new_t = t - quotient * temp
            t = temp

            # (r, newr) := (newr, r − quotient × newr)
            temp = new_r
            new_r = r - quotient * temp
            r = temp

        if r > 1:
            raise RuntimeError('a is not invertible')

        if t < 0:
            t += n

        return t

    @staticmethod
    def modulus(a: int, n: int) -> int:
        return a % n

    @staticmethod
    def modular_exponentiation(base: int, exponent: int, modulus: int) -> int:
        # return pow(base, exponent, modulus)
        if modulus == 1:
            return 0

        result = 1
        base = Utility.modulus(base, modulus)
        while exponent > 0:
            if exponent & 1:
                result = Utility.modulus(result * base, modulus)
            exponent >>= 1
            base = Utility.modulus(base * base, modulus)
        return result

    @staticmethod
    def get_bit_length(a: int) -> int:
        return len(bin(a)[2:])


if __name__ == '__main__':
    for i in range(5, 100):
        res = Utility.is_prime(i, 10)
        if res:
            print(f'{i} is probable prime')
        else:
            print(f'{i} is composite')
