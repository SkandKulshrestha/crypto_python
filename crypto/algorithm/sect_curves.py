# from import internal library
from utility import Utility

sect_curves = {
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect163k1': (
        163,  # m
        Utility.remove_space_and_convert_to_int('''
            163 7 6 3 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
            00 00000000 00000000 00000000 00000000 00000001
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            00 00000000 00000000 00000000 00000000 00000001
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            02 FE13C053 7BBC11AC AA07D793 DE4E6D5E 5C94EEE8
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            02 89070FB0 5D38FF58 321F2E80 0536D538 CCDAA3D9
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            04 00000000 00000000 00020108 A2E0CC0D 99F8A5EF
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            02
        '''),  # h
        None  # S
    ),
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect163r1': (
        163,  # m
        Utility.remove_space_and_convert_to_int('''
            163 7 6 3 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
            07 B6882CAA EFA84F95 54FF8428 BD88E246 D2782AE2
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            07 13612DCD DCB40AAB 946BDA29 CA91F73A F958AFD9
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            03 69979697 AB438977 89566789 567F787A 7876A654
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            00 435EDB42 EFAFB298 9D51FEFC E3C80988 F41FF883
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            03 FFFFFFFF FFFFFFFF FFFF48AA B689C29C A710279B
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            02
        '''),  # h
        Utility.remove_space_and_convert_to_int('''
            24B7B137 C8A14D69 6E676875 6151756F D0DA2E5C
        '''),  # S
    ),
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect163r2': (
        163,  # m
        Utility.remove_space_and_convert_to_int('''
            163 7 6 3 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
            00 00000000 00000000 00000000 00000000 00000001
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            02 0A601907 B8C953CA 1481EB10 512F7874 4A3205FD
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            03 F0EBA162 86A2D57E A0991168 D4994637 E8343E36
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            00 D51FBC6C 71A0094F A2CDD545 B11C5C0C 797324F1
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            04 00000000 00000000 000292FE 77E70C12 A4234C33
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            02
        '''),  # h
        Utility.remove_space_and_convert_to_int('''
            85E25BFE 5C86226C DB12016F 7553F9D0 E693A268
        '''),  # S
    ),
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect233k1': (
        233,  # m
        Utility.remove_space_and_convert_to_int('''
            233 74 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
                0000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
                0000 00000000 00000000 00000000 00000000 00000000 00000000
            00000001
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
                0172 32BA853A 7E731AF1 29F22FF4 149563A4 19C26BF5 0A4C9D6E
            EFAD6126
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
                01DB 537DECE8 19B7F70F 555A67C4 27A8CD9B F18AEB9B 56E0C110
            56FAE6A3
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
                0080 00000000 00000000 00000000 00069D5B B915BCD4 6EFB1AD5
            F173ABDF
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            04
        '''),  # h
        None  # S
    ),
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect233r1': (
        233,  # m
        Utility.remove_space_and_convert_to_int('''
            233 74 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
                0000 00000000 00000000 00000000 00000000 00000000 00000000
            00000001
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
                0066 647EDE6C 332C7F8C 0923BB58 213B333B 20E9CE42 81FE115F
            7D8F90AD
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
                00FA C9DFCBAC 8313BB21 39F1BB75 5FEF65BC 391F8B36 F8F8EB73
            71FD558B
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
                0100 6A08A419 03350678 E58528BE BF8A0BEF F867A7CA 36716F7E
            01F81052
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
                0100 00000000 00000000 00000000 0013E974 E72F8A69 22031D26
            03CFE0D7
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            02
        '''),  # h
        Utility.remove_space_and_convert_to_int('''
            74D59FF0 7F6B413D 0EA14B34 4B20A2DB 049B50C3
        '''),  # S
    ),
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect239k1': (
        239,  # m
        Utility.remove_space_and_convert_to_int('''
            239 158 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
                0000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
                0000 00000000 00000000 00000000 00000000 00000000 00000000
            00000001
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
                29A0 B6A887A9 83E97309 88A68727 A8B2D126 C44CC2CC 7B2A6555
            193035DC
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
                7631 0804F12E 549BDB01 1C103089 E73510AC B275FC31 2A5DC6B7
            6553F0CA
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
                2000 00000000 00000000 00000000 005A79FE C67CB6E9 1F1C1DA8
            00E478A5
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            04
        '''),  # h
        None  # S
    ),
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect283k1': (
        283,  # m
        Utility.remove_space_and_convert_to_int('''
            283 12 7 5 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000000
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000001
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            0503213F 78CA4488 3F1A3B81 62F188E5 53CD265F 23C1567A 16876913
            B0C2AC24 58492836
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            01CCDA38 0F1C9E31 8D90F95D 07E5426F E87E45C0 E8184698 E4596236
            4E341161 77DD2259
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            01FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFE9AE 2ED07577 265DFF7F
            94451E06 1E163C61
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            04
        '''),  # h
        None  # S
    ),
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect283r1': (
        283,  # m
        Utility.remove_space_and_convert_to_int('''
            283 12 7 5 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000001
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            027B680A C8B8596D A5A4AF8A 19A0303F CA97FD76 45309FA2 A581485A
            F6263E31 3B79A2F5
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            05F93925 8DB7DD90 E1934F8C 70B0DFEC 2EED25B8 557EAC9C 80E2E198
            F8CDBECD 86B12053
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            03676854 FE24141C B98FE6D4 B20D02B4 516FF702 350EDDB0 826779C8
            13F0DF45 BE8112F4
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            03FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFEF90 399660FC 938A9016
            5B042A7C EFADB307
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            02
        '''),  # h
        Utility.remove_space_and_convert_to_int('''
            77E2B073 70EB0F83 2A6DD5B6 2DFC88CD 06BB84BE
        '''),  # S
    ),
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect409k1': (
        409,  # m
        Utility.remove_space_and_convert_to_int('''
            409 87 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000000 00000000 00000000 00000000 00000000
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000000 00000000 00000000 00000000 00000001
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            0060F05F 658F49C1 AD3AB189 0F718421 0EFD0987 E307C84C 27ACCFB8
            F9F67CC2 C460189E B5AAAA62 EE222EB1 B35540CF E9023746
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            01E36905 0B7C4E42 ACBA1DAC BF04299C 3460782F 918EA427 E6325165
            E9EA10E3 DA5F6C42 E9C55215 AA9CA27A 5863EC48 D8E0286B
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
              7FFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFE5F
            83B2D4EA 20400EC4 557D5ED3 E3E7CA5B 4B5C83B8 E01E5FCF
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            02
        '''),  # h
        None  # S
    ),
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect409r1': (
        409,  # m
        Utility.remove_space_and_convert_to_int('''
            409 87 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000000 00000000 00000000 00000000 00000001
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            0021A5C2 C8EE9FEB 5C4B9A75 3B7B476B 7FD6422E F1F3DD67 4761FA99
            D6AC27C8 A9A197B2 72822F6C D57A55AA 4F50AE31 7B13545F
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            015D4860 D088DDB3 496B0C60 64756260 441CDE4A F1771D4D B01FFE5B
            34E59703 DC255A86 8A118051 5603AEAB 60794E54 BB7996A7
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            0061B1CF AB6BE5F3 2BBFA783 24ED106A 7636B9C5 A7BD198D 0158AA4F
            5488D08F 38514F1F DF4B4F40 D2181B36 81C364BA 0273C706
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            01000000 00000000 00000000 00000000 00000000 00000000 000001E2
            AAD6A612 F33307BE 5FA47C3C 9E052F83 8164CD37 D9A21173
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            02
        '''),  # h
        Utility.remove_space_and_convert_to_int('''
            4099B5A4 57F9D69F 79213D09 4C4BCD4D 4262210B
        '''),  # S
    ),
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect571k1': (
        571,  # m
        Utility.remove_space_and_convert_to_int('''
            571 10 5 2 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000000 00000000 00000000
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000000 00000000 00000001
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            026EB7A8 59923FBC 82189631 F8103FE4 AC9CA297 0012D5D4 60248048
            01841CA4 43709584 93B205E6 47DA304D B4CEB08C BBD1BA39 494776FB
            988B4717 4DCA88C7 E2945283 A01C8972
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            0349DC80 7F4FBF37 4F4AEADE 3BCA9531 4DD58CEC 9F307A54 FFC61EFC
            006D8A2C 9D4979C0 AC44AEA7 4FBEBBB9 F772AEDC B620B01A 7BA7AF1B
            320430C8 591984F6 01CD4C14 3EF1C7A3
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            02000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000000 131850E1 F19A63E4 B391A8DB 917F4138 B630D84B
            E5D63938 1E91DEB4 5CFE778F 637C1001
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            04
        '''),  # h
        None  # S
    ),
    #  T = (m, f(x), a, b, G, n, h, S)
    'sect571r1': (
        571,  # m
        Utility.remove_space_and_convert_to_int('''
            571 10 5 2 0
        '''),  # f(x)
        Utility.remove_space_and_convert_to_int('''
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000000 00000000 00000000 00000000 00000000 00000000
            00000000 00000000 00000000 00000001
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            02F40E7E 2221F295 DE297117 B7F3D62F 5C6A97FF CB8CEFF1 CD6BA8CE
            4A9A18AD 84FFABBD 8EFA5933 2BE7AD67 56A66E29 4AFD185A 78FF12AA
            520E4DE7 39BACA0C 7FFEFF7F 2955727A
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            0303001D 34B85629 6C16C0D4 0D3CD775 0A93D1D2 955FA80A A5F40FC8
            DB7B2ABD BDE53950 F4C0D293 CDD711A3 5B67FB14 99AE6003 8614F139
            4ABFA3B4 C850D927 E1E7769C 8EEC2D19
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            037BF273 42DA639B 6DCCFFFE B73D69D7 8C6C27A6 009CBBCA 1980F853
            3921E8A6 84423E43 BAB08A57 6291AF8F 461BB2A8 B3531D2F 0485C19B
            16E2F151 6E23DD3C 1A4827AF 1B8AC15B
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            03FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF
            FFFFFFFF FFFFFFFF E661CE18 FF559873 08059B18 6823851E C7DD9CA1
            161DE93D 5174D66E 8382E9BB 2FE84E47
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            02
        '''),  # h
        Utility.remove_space_and_convert_to_int('''
            2AA058F7 3A0E33AB 486B0F61 0410C53A 7F132310
        '''),  # S
    ),
}
