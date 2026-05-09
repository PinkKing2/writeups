import struct, sys

LD=0x00; LDX=0x01; ST=0x02; ALU=0x04; JMP=0x05; RET=0x06; MISC=0x07

W=0x00; H=0x08; B=0x10

IMM=0x00; ABS=0x20; IND=0x40; MEM=0x60; MSH=0xa0

ADD=0x00; OR=0x40; LSH=0x60; RSH=0x70; XOR=0xa0
JEQ=0x10

aluname = {ADD: 'add', OR: 'or', LSH: 'lsh', RSH: 'rsh', XOR: 'xor'}
sizename  = {W:'', H:'h', B:'b'}

def dis(i, code, jt, jf, k):
    inst_class = code & 0x07;
    size = code & 0x18;
    mode = code & 0xe0
    op = code & 0xf0;
    src = code & 0x08;
    s = sizename.get(size, '?')
    if inst_class == LD:
        if mode == IMM:
            return f"ld #{k:#x}"
        if mode == ABS:
            return f"ld{s} [{k}]"
        if mode == IND:
            return f"ld{s} [x+{k}]"
        if mode == MEM:
            return f"ld M[{k}]"
    elif inst_class == LDX:
        if mode == MEM:
            return f"ldx M[{k}]"
    elif inst_class == ST:
        return f"st M[{k}]"
    elif inst_class == ALU:
        name = aluname.get(op,'?')
        return f"{name} x" if src else f"{name} #{k:#x}"
    elif inst_class == JMP:
        operand = "x" if src else f"#{k:#x}"
        return f"jeq {operand}, jt {i+1+jt}, jf {i+1+jf}"
    elif inst_class == RET:
        return f"ret #{k:#x}"
    elif inst_class == MISC:
        return "tax"

    return f"??? code=0x{code:04x}"

def main():
    with open("filter.bin", "rb") as f:
        data = f.read()
    inst_length = len(data) // 8
    for i in range(inst_length):
        code, jt, jf, k = struct.unpack_from('<HBBI', data, i*8)
        print(f"{i:4d}: {dis(i, code, jt, jf, k)}")

if __name__ == "__main__":
    main()
