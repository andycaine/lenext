import lenext


def test_lenext():
    secret = b'mysecretkey'
    orig_msg = b'my message'
    orig_mac = lenext.md5(secret + orig_msg)
    print(orig_mac)

    tampered_mac, tampered_msg = lenext.lenext(orig_mac, len(secret), orig_msg,
                                               b'this has been tampered with')

    # test that we have generated a MAC that checks out without knowledge of 
    # the secret
    assert tampered_mac == lenext.md5(secret + tampered_msg)


def test_md5():
    assert lenext.md5(b'') == 'd41d8cd98f00b204e9800998ecf8427e'
    assert lenext.md5(b'abc') == '900150983cd24fb0d6963f7d28e17f72'
    assert lenext.md5(b'abc'.ljust(65, b'a')) == \
        '38f66d46c1806a90c9adea77c0315530'


def test_chunk_single_block():
    chunks = lenext.chunk('abcd', 4)
    assert chunks == ['abcd']


def test_chunk_two_blocks():
    chunks = lenext.chunk('abcd1234', 4)
    assert chunks == ['abcd', '1234']


def test_f():
    assert lenext.fn_f(1, 2, 3) == 0x02
    assert lenext.fn_f(4, 2, 1) == 0x01
    assert lenext.fn_f(4, 2, 32) == 0x20


def test_ff():
    a, b, c, d = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
    x0 = 0x80636261
    assert lenext.fn_ff(a, b, c, d, x0, 7, 0xd76aa478) == 0xd6d117b4


def test_g():
    assert lenext.fn_g(1, 2, 3) == 0x01
    assert lenext.fn_g(4, 2, 1) == 0x02
    assert lenext.fn_g(4, 2, 32) == 0x02


def test_gg():
    a, b, c, d = (0xdda9b9a6, 0x72aff2e0, 0xe396856b, 0xa1051895)
    assert lenext.fn_gg(a, b, c, d, 0, 5, 0xf61e2562) == 0x3e9e9126


def test_h():
    assert lenext.fn_h(1, 2, 3) == 0x00
    assert lenext.fn_h(4, 2, 1) == 0x07
    assert lenext.fn_h(4, 2, 32) == 0x26


def test_i():
    assert lenext.fn_i(1, 2, 3) == 0xffffffff
    assert lenext.fn_i(4, 2, 1) == 0xfffffffc
    assert lenext.fn_i(4, 2, 32) == 0xffffffdd


def test_rotate_left():
    assert lenext.rotate_left(0x01, 2) == 0x04
    assert lenext.rotate_left(0xf0000000, 4) == 0x0000000f


def test_decode():
    decoded = lenext.decode(b'\x61\x62\x63\x80\x18\x00\x00\x00')
    assert decoded == [0x80636261, 0x00000018]


def test_encode():
    encoded = lenext.encode([0x80636261, 0x00000018])
    assert encoded == b'\x61\x62\x63\x80\x18\x00\x00\x00'


def test_transform():
    block = b'\x61\x62\x63\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00' \
            b'\x00\x00\x00\x00'
    state = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
    a, b, c, d = lenext.transform(state, block)
    assert a == 0x98500190
    assert b == 0xb04fd23c
    assert c == 0x7d3f96d6
    assert d == 0x727fe128


def test_append_length():
    m = lenext.append_length(bytes(56), 55)
    assert len(m) == 64
    assert m[56:] == b'\xb8\x01\x00\x00\x00\x00\x00\x00'


def test_pad_len():
    assert lenext.pad_len(bytes(56)) == 56 + 64
    assert lenext.pad_len(bytes(57)) == 56 + 64
    assert lenext.pad_len(bytes(55)) == 56
    assert lenext.pad_len(bytes(64 + 56)) == 64 + 56 + 64
    assert lenext.pad_len(bytes(64 + 57)) == 64 + 56 + 64
    assert lenext.pad_len(bytes(64 + 55)) == 64 + 56


def test_pad_120_byte_message():
    # should add 1 '1' bit and (512 - 1) '0' bits
    padded = lenext.pad(bytes(120))
    assert len(padded) == 120 + 64
    assert padded[120] == 0x80  # 1 '1' bit followed by 7 '0' bits
    assert all([b == 0x00 for b in padded[121:]])  # all remaining bits are '0'


def test_pad_119_byte_message():
    # should add 1 '1' bit and 0 '0' bits
    padded = lenext.pad(bytes(119))
    assert len(padded) == 120
    assert padded[119] == 0x80  # 1 '1' bit followed by 7 '0' bits


def test_pad_56_byte_message():
    # should add 1 '1' bit and (512 - 1) '0' bits
    padded = lenext.pad(bytes(56))
    assert len(padded) == 56 + 64
    assert padded[56] == 0x80  # 1 '1' bit followed by 7 '0' bits
    assert all([b == 0x00 for b in padded[57:]])  # all remaining bits are '0'


def test_pad_57_byte_message():
    # should add 1 '1' bit and (512 - 1) '0' bits
    padded = lenext.pad(bytes(57))
    assert len(padded) == 56 + 64
    assert padded[57] == 0x80  # 1 '1' bit followed by 7 '0' bits
    assert all([b == 0x00 for b in padded[58:]])  # all remaining bits are '0'


def test_pad_55_byte_message():
    # should add 1 '1' bit and 0 '0' bits
    padded = lenext.pad(bytes(55))
    assert len(padded) == 56
    assert padded[55] == 0x80  # 1 '1' bit followed by 7 '0' bits
