# from import internal library
from utility import Utility

brainpool_curves = {
    # T = (p, a, b, G, n, h, S)
    'brainpoolP160r1': (
        Utility.remove_space_and_convert_to_int('''
            E95E4A5F 737059DC 60DFC7AD 95B3D813 9515620F
        '''),  # p
        Utility.remove_space_and_convert_to_int('''
            340E7BE2 A280EB74 E2BE61BA DA745D97 E8F7C300
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            1E589A85 95423412 134FAA2D BDEC95C8 D8675E58
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            BED5AF16 EA3F6A4F 62938C46 31EB5AF7 BDBCDBC3
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            1667CB47 7A1A8EC3 38F94741 669C9763 16DA6321
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            E95E4A5F 737059DC 60DF5991 D4502940 9E60FC09
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            01
        '''),  # h
        None  # S
    ),
    # T = (p, a, b, G, n, h, S)
    'brainpoolP192r1': (
        Utility.remove_space_and_convert_to_int('''
            C302F41D 932A36CD A7A34630 93D18DB7 8FCE476D E1A86297
        '''),  # p
        Utility.remove_space_and_convert_to_int('''
            6A911740 76B1E0E1 9C39C031 FE8685C1 CAE040E5 C69A28EF
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            469A28EF 7C28CCA3 DC721D04 4F4496BC CA7EF414 6FBF25C9
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            C0A0647E AAB6A487 53B033C5 6CB0F090 0A2F5C48 53375FD6
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            14B69086 6ABD5BB8 8B5F4828 C1490002 E6773FA2 FA299B8F
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            C302F41D 932A36CD A7A3462F 9E9E916B 5BE8F102 9AC4ACC1
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            01
        '''),  # h
        None  # S
    ),
    # T = (p, a, b, G, n, h, S)
    'brainpoolP224r1': (
        Utility.remove_space_and_convert_to_int('''
            D7C134AA 26436686 2A183025 75D1D787 B09F0757 97DA89F5 7EC8C0FF
        '''),  # p
        Utility.remove_space_and_convert_to_int('''
            68A5E62C A9CE6C1C 299803A6 C1530B51 4E182AD8 B0042A59 CAD29F43
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            2580F63C CFE44138 870713B1 A92369E3 3E2135D2 66DBB372 386C400B
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            0D9029AD 2C7E5CF4 340823B2 A87DC68C 9E4CE317 4C1E6EFD EE12C07D
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            58AA56F7 72C0726F 24C6B89E 4ECDAC24 354B9E99 CAA3F6D3 761402CD
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            D7C134AA 26436686 2A183025 75D0FB98 D116BC4B 6DDEBCA3 A5A7939F
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            01
        '''),  # h
        None  # S
    ),
    # T = (p, a, b, G, n, h, S)
    'brainpoolP256r1': (
        Utility.remove_space_and_convert_to_int('''
            A9FB57DB A1EEA9BC 3E660A90 9D838D72 6E3BF623 D5262028 2013481D
            1F6E5377
        '''),  # p
        Utility.remove_space_and_convert_to_int('''
            7D5A0975 FC2C3057 EEF67530 417AFFE7 FB8055C1 26DC5C6C E94A4B44
            F330B5D9
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            26DC5C6C E94A4B44 F330B5D9 BBD77CBF 95841629 5CF7E1CE 6BCCDC18
            FF8C07B6
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            8BD2AEB9 CB7E57CB 2C4B482F FC81B7AF B9DE27E1 E3BD23C2 3A4453BD
            9ACE3262
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            547EF835 C3DAC4FD 97F8461A 14611DC9 C2774513 2DED8E54 5C1D54C7
            2F046997
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            A9FB57DB A1EEA9BC 3E660A90 9D838D71 8C397AA3 B561A6F7 901E0E82
            974856A7
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            01
        '''),  # h
        None  # S
    ),
    # T = (p, a, b, G, n, h, S)
    'brainpoolP320r1': (
        Utility.remove_space_and_convert_to_int('''
            D35E4720 36BC4FB7 E13C785E D201E065 F98FCFA6 F6F40DEF 4F92B9EC
            7893EC28 FCD412B1 F1B32E27
        '''),  # p
        Utility.remove_space_and_convert_to_int('''
            3EE30B56 8FBAB0F8 83CCEBD4 6D3F3BB8 A2A73513 F5EB79DA 66190EB0
            85FFA9F4 92F375A9 7D860EB4
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            52088394 9DFDBC42 D3AD1986 40688A6F E13F4134 9554B49A CC31DCCD
            88453981 6F5EB4AC 8FB1F1A6
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            43BD7E9A FB53D8B8 5289BCC4 8EE5BFE6 F20137D1 0A087EB6 E7871E2A
            10A599C7 10AF8D0D 39E20611
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            14FDD055 45EC1CC8 AB409324 7F77275E 0743FFED 117182EA A9C77877
            AAAC6AC7 D35245D1 692E8EE1
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            D35E4720 36BC4FB7 E13C785E D201E065 F98FCFA5 B68F12A3 2D482EC7
            EE8658E9 8691555B 44C59311
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            01
        '''),  # h
        None  # S
    ),
    # T = (p, a, b, G, n, h, S)
    'brainpoolP384r1': (
        Utility.remove_space_and_convert_to_int('''
            8CB91E82 A3386D28 0F5D6F7E 50E641DF 152F7109 ED5456B4 12B1DA19
            7FB71123 ACD3A729 901D1A71 87470013 3107EC53
        '''),  # p
        Utility.remove_space_and_convert_to_int('''
            7BC382C6 3D8C150C 3C72080A CE05AFA0 C2BEA28E 4FB22787 139165EF
            BA91F90F 8AA5814A 503AD4EB 04A8C7DD 22CE2826
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            04A8C7DD 22CE2826 8B39B554 16F0447C 2FB77DE1 07DCD2A6 2E880EA5
            3EEB62D5 7CB43902 95DBC994 3AB78696 FA504C11
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            1D1C64F0 68CF45FF A2A63A81 B7C13F6B 8847A3E7 7EF14FE3 DB7FCAFE
            0CBD10E8 E826E034 36D646AA EF87B2E2 47D4AF1E
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            8ABE1D75 20F9C2A4 5CB1EB8E 95CFD552 62B70B29 FEEC5864 E19C054F
            F9912928 0E464621 77918111 42820341 263C5315
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            8CB91E82 A3386D28 0F5D6F7E 50E641DF 152F7109 ED5456B3 1F166E6C
            AC0425A7 CF3AB6AF 6B7FC310 3B883202 E9046565
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            01
        '''),  # h
        None  # S
    ),
    # T = (p, a, b, G, n, h, S)
    'brainpoolP512r1': (
        Utility.remove_space_and_convert_to_int('''
            AADD9DB8 DBE9C48B 3FD4E6AE 33C9FC07 CB308DB3 B3C9D20E D6639CCA
            70330871 7D4D9B00 9BC66842 AECDA12A E6A380E6 2881FF2F 2D82C685
            28AA6056 583A48F3
        '''),  # p
        Utility.remove_space_and_convert_to_int('''
            7830A331 8B603B89 E2327145 AC234CC5 94CBDD8D 3DF91610 A83441CA
            EA9863BC 2DED5D5A A8253AA1 0A2EF1C9 8B9AC8B5 7F1117A7 2BF2C7B9
            E7C1AC4D 77FC94CA
        '''),  # a
        Utility.remove_space_and_convert_to_int('''
            3DF91610 A83441CA EA9863BC 2DED5D5A A8253AA1 0A2EF1C9 8B9AC8B5
            7F1117A7 2BF2C7B9 E7C1AC4D 77FC94CA DC083E67 984050B7 5EBAE5DD
            2809BD63 8016F723
        '''),  # b
        Utility.remove_space_and_convert_to_int('''
            81AEE4BD D82ED964 5A21322E 9C4C6A93 85ED9F70 B5D916C1 B43B62EE
            F4D0098E FF3B1F78 E2D0D48D 50D1687B 93B97D5F 7C6D5047 406A5E68
            8B352209 BCB9F822
        '''),  # g_x
        Utility.remove_space_and_convert_to_int('''
            7DDE385D 566332EC C0EABFA9 CF7822FD F209F700 24A57B1A A000C55B
            881F8111 B2DCDE49 4A5F485E 5BCA4BD8 8A2763AE D1CA2B2F A8F05406
            78CD1E0F 3AD80892
        '''),  # g_y
        Utility.remove_space_and_convert_to_int('''
            AADD9DB8 DBE9C48B 3FD4E6AE 33C9FC07 CB308DB3 B3C9D20E D6639CCA
            70330870 553E5C41 4CA92619 41866119 7FAC1047 1DB1D381 085DDADD
            B5879682 9CA90069
        '''),  # n
        Utility.remove_space_and_convert_to_int('''
            01
        '''),  # h
        None  # S
    )
}
