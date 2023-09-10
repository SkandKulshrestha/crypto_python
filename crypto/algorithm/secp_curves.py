# from import external library
from utility import Utility

secp_curves = {
    # T = (p, a, b, G, n, h, S)
    'secp256k1': (
        int(Utility.remove_space('''
            FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE
            FFFFFC2F
        '''), 16),
        int(Utility.remove_space('''
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000
        '''), 16),
        int(Utility.remove_space('''
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000007
        '''), 16),
        int(Utility.remove_space('''
            79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B
            16F81798
        '''), 16),
        int(Utility.remove_space('''
            483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F
            FB10D4B8
        '''), 16),
        int(Utility.remove_space('''
            FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C
            D0364141
        '''), 16),
        int(Utility.remove_space('''
            01
        '''), 16),
        int(Utility.remove_space('''
            00000000
        '''), 16)
    ),
    # T = (p, a, b, G, n, h, S)
    'secp256r1': (
        int(Utility.remove_space('''
            FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF
            FFFFFFFF
        '''), 16),
        int(Utility.remove_space('''
            FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF
            FFFFFFFC
        '''), 16),
        int(Utility.remove_space('''
            5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E
            27D2604B
        '''), 16),
        int(Utility.remove_space('''
            6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945
            D898C296
        '''), 16),
        int(Utility.remove_space('''
            4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068
            37BF51F5
        '''), 16),
        int(Utility.remove_space('''
            FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2
            FC632551
        '''), 16),
        int(Utility.remove_space('''
            01
        '''), 16),
        int(Utility.remove_space('''
            C49D3608 86E70493 6A6678E1 139D26B7 819F7E90
        '''), 16)
    )
}
