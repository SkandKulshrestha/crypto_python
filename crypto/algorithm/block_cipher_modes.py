# from import external library
from enum import Enum, IntEnum

# from import internal library
from des import DES
from tdes import TDES
from aes import AES


class SymmetricAlgorithm(Enum):
    # instance of DES algorithm
    DES = DES

    # instance of TDES algorithm
    TDES = TDES

    # instance of AES algorithm
    AES = AES


class BlockCipherModesOfOperation(IntEnum):
    CONFIDENTIAL = 0xFF00
    INTEGRITY = 0x80FF

    # 1-bit Chaining Cipher: CBC, OFB, CFB, CTR
    CHAINING_BIT = 0x8000

    # 3-bit Block Cipher: ECB, CBC
    BLOCK_CIPHER = 0x7000

    # 4-bit Stream Cipher: OFB, CFB, CTR, GCTR
    STREAM_CIPHER = 0x0F00

    # 1-bit Message Authentication Code
    MAC_BIT = 0x0080

    # 7-bit Message Authentication Code: CBC-MAC, CMAC, GMAC, MAC-ALGO
    MAC = 0x007F


class BlockCipherConfidentialityModes(IntEnum):
    # Electronic Codebook
    ECB = 0x1000

    # Cipher Block Chaining
    # 0xA000
    CBC = BlockCipherModesOfOperation.CHAINING_BIT | 0x2000

    # Propagating CBC
    # 0xB000
    PCBC = BlockCipherModesOfOperation.CHAINING_BIT | 0x3000

    # Output Feedback
    # 0x8100
    OFB = BlockCipherModesOfOperation.CHAINING_BIT | 0x0100

    # Cipher Feedback
    # 0x8200
    CFB = BlockCipherModesOfOperation.CHAINING_BIT | 0x0200

    # Counter
    # 0x8400
    CTR = BlockCipherModesOfOperation.CHAINING_BIT | 0x0400

    # Galois Counter
    # 0x8800
    GCTR = BlockCipherModesOfOperation.CHAINING_BIT | 0x0800


class BlockCipherAuthenticationModes(IntEnum):
    # Cipher Block Chaining-Message Authentication Code
    # 0x8080
    CBC_MAC = BlockCipherModesOfOperation.CHAINING_BIT | BlockCipherModesOfOperation.MAC_BIT | 0x0000

    #
    # 0x80C0
    CMAC = BlockCipherModesOfOperation.CHAINING_BIT | BlockCipherModesOfOperation.MAC_BIT | 0x0040

    # Galois/Counter - Message Authentication Code
    # 0x80A0
    GMAC = BlockCipherModesOfOperation.CHAINING_BIT | BlockCipherModesOfOperation.MAC_BIT | 0x0020

    #
    # 0x8083
    MAC_ALGO3 = BlockCipherModesOfOperation.CHAINING_BIT | BlockCipherModesOfOperation.MAC_BIT | 0x0003

    #
    # 0x8084
    MAC_ALGO4 = BlockCipherModesOfOperation.CHAINING_BIT | BlockCipherModesOfOperation.MAC_BIT | 0x0004


# Authenticated Encryption with Additional Data
class AEADModes(IntEnum):
    # Counter with Cipher Block Chaining-Message Authentication Code
    # 0x8480
    CCM = BlockCipherConfidentialityModes.CTR | BlockCipherAuthenticationModes.CBC_MAC

    # Galois/Counter Mode
    # 0x84A0
    GCM = BlockCipherConfidentialityModes.CTR | BlockCipherAuthenticationModes.GMAC
