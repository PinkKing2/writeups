keys = [
    (11, 21, 0x1e),
    (1, 3, 0x6),
    (5, 29, 0xc),
    (13, 7, 0x30),
    (31, 24, 0x9),
    (1, 14, 0x4),
    (8, 11, 0x1d),
    (18, 14, 0x1e),
    (27, 23, 0x00),
    (9, 6, 0x1a),
    (28, 7, 0x31),
    (22, 14, 0x5),
    (11, 22, 0x1b),
    (23, 29, 0x6),
    (20, 7, 0x33),
    (26, 11, 0x8),
    (25, 1, 0x37),
    (12, 30, 0x1d),
    (0, 14, 0xf),
    (15, 1, 0xc),
    (30, 24, 0x00),
    (24, 14, 0x2),
    (17, 21, 0x18),
    (16, 25, 0x00),
    (2, 11, 0x13),
    (29, 7, 0x36),
    (10, 9, 0x13),
    (6, 15, 0x8),
    (19, 3, 0x7),
    (4, 7, 0x31),
    (7, 14, 0x33)
]

password = [None]*32
password[14] = 0xef ^ 0x83

changed = True
while changed:
    changed = False
    for a, b, constant in keys:
        if password[a] is not None and password[b] is None:
            password[b] = password[a] ^ constant
            changed = True
        elif password[b] is not None and password[a] is None:
            password[a] = password[b] ^ constant
            changed = True

print("".join(chr(c) for c in password))