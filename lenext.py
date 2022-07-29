import argparse
import functools
import math


S11 = 7
S12 = 12
S13 = 17
S14 = 22
S21 = 5
S22 = 9
S23 = 14
S24 = 20
S31 = 4
S32 = 11
S33 = 16
S34 = 23
S41 = 6
S42 = 10
S43 = 15
S44 = 21


def lenext(h, key_len, orig_msg, extension):
    # Create state from hash h
    state = decode(bytes.fromhex(h))

    # Construct a tampered message with the desired extension text.
    # In order to get the right hash we need to pad and append the length of 
    # the original message before adding the extension
    tampered_msg = pad(orig_msg)[:-key_len]
    tampered_msg = append_length(tampered_msg, len(orig_msg) + key_len)
    tampered_msg += extension

    # Pad extension and append length of tampered message
    extension = pad(extension)
    extension = append_length(extension, len(tampered_msg) + key_len)

    # Transform
    state = transform(state, extension)

    # Create new hash from state
    return (encode(state).hex(), tampered_msg)


def pad_and_append_length(m):
    length = len(m)
    m = pad(m)
    m = append_length(m, length)
    return m


def md5(m):
    if m == b'':
        return 'd41d8cd98f00b204e9800998ecf8427e'

    m = pad_and_append_length(m)

    state = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
    for c in chunk(m, 64):
        state = transform(state, c)
    
    return encode(state).hex()


def chunk(m, length):
    return [m[i:i+length] for i in range(0, len(m), length)]


def pad_len(m):
    """ Return the length to pad this message to.
    
    Always need to be padded at least 1 byte for the '1' bit.  Then needs to
    be padded to 56 modulo 64.  In other words, padded to 8 bytes short of
    the 64 byte boundary.
    """
    return (math.ceil((len(m) + 9) / 64) * 64) - 8


def pad(m):
    padded = bytearray(m.ljust(pad_len(m), b'\x00'))
    padded[len(m)] = 0x80
    return bytes(padded)


def append_length(m, length):
    return m + (length * 8).to_bytes(8, 'little')


def transform(state, block):
    a, b, c, d = state
    x = decode(block)

    # Round 1
    a = fn_ff(a, b, c, d, x[0], S11, 0xd76aa478)  # 1
    d = fn_ff(d, a, b, c, x[1], S12, 0xe8c7b756)  # 2 
    c = fn_ff(c, d, a, b, x[2], S13, 0x242070db)  # 3 
    b = fn_ff(b, c, d, a, x[3], S14, 0xc1bdceee)  # 4 
    a = fn_ff(a, b, c, d, x[4], S11, 0xf57c0faf)  # 5 
    d = fn_ff(d, a, b, c, x[5], S12, 0x4787c62a)  # 6 
    c = fn_ff(c, d, a, b, x[6], S13, 0xa8304613)  # 7 
    b = fn_ff(b, c, d, a, x[7], S14, 0xfd469501)  # 8 
    a = fn_ff(a, b, c, d, x[8], S11, 0x698098d8)  # 9 
    d = fn_ff(d, a, b, c, x[9], S12, 0x8b44f7af)  # 10
    c = fn_ff(c, d, a, b, x[10], S13, 0xffff5bb1)  # 11
    b = fn_ff(b, c, d, a, x[11], S14, 0x895cd7be)  # 12
    a = fn_ff(a, b, c, d, x[12], S11, 0x6b901122)  # 13
    d = fn_ff(d, a, b, c, x[13], S12, 0xfd987193)  # 14
    c = fn_ff(c, d, a, b, x[14], S13, 0xa679438e)  # 15
    b = fn_ff(b, c, d, a, x[15], S14, 0x49b40821)  # 16

    # Round 2
    a = fn_gg(a, b, c, d, x[1], S21, 0xf61e2562)  # 17
    d = fn_gg(d, a, b, c, x[6], S22, 0xc040b340)  # 18
    c = fn_gg(c, d, a, b, x[11], S23, 0x265e5a51)  # 19
    b = fn_gg(b, c, d, a, x[0], S24, 0xe9b6c7aa)  # 20
    a = fn_gg(a, b, c, d, x[5], S21, 0xd62f105d)  # 21
    d = fn_gg(d, a, b, c, x[10], S22,  0x2441453)  # 22
    c = fn_gg(c, d, a, b, x[15], S23, 0xd8a1e681)  # 23
    b = fn_gg(b, c, d, a, x[4], S24, 0xe7d3fbc8)  # 24
    a = fn_gg(a, b, c, d, x[9], S21, 0x21e1cde6)  # 25
    d = fn_gg(d, a, b, c, x[14], S22, 0xc33707d6)  # 26
    c = fn_gg(c, d, a, b, x[3], S23, 0xf4d50d87)  # 27
    b = fn_gg(b, c, d, a, x[8], S24, 0x455a14ed)  # 28
    a = fn_gg(a, b, c, d, x[13], S21, 0xa9e3e905)  # 29
    d = fn_gg(d, a, b, c, x[2], S22, 0xfcefa3f8)  # 30
    c = fn_gg(c, d, a, b, x[7], S23, 0x676f02d9)  # 31
    b = fn_gg(b, c, d, a, x[12], S24, 0x8d2a4c8a)  # 32

    # Round 3
    a = fn_hh(a, b, c, d, x[5], S31, 0xfffa3942)  # 33
    d = fn_hh(d, a, b, c, x[8], S32, 0x8771f681)  # 34
    c = fn_hh(c, d, a, b, x[11], S33, 0x6d9d6122)  # 35
    b = fn_hh(b, c, d, a, x[14], S34, 0xfde5380c)  # 36
    a = fn_hh(a, b, c, d, x[1], S31, 0xa4beea44)  # 37
    d = fn_hh(d, a, b, c, x[4], S32, 0x4bdecfa9)  # 38
    c = fn_hh(c, d, a, b, x[7], S33, 0xf6bb4b60)  # 39
    b = fn_hh(b, c, d, a, x[10], S34, 0xbebfbc70)  # 40
    a = fn_hh(a, b, c, d, x[13], S31, 0x289b7ec6)  # 41
    d = fn_hh(d, a, b, c, x[0], S32, 0xeaa127fa)  # 42
    c = fn_hh(c, d, a, b, x[3], S33, 0xd4ef3085)  # 43
    b = fn_hh(b, c, d, a, x[6], S34,  0x4881d05)  # 44
    a = fn_hh(a, b, c, d, x[9], S31, 0xd9d4d039)  # 45
    d = fn_hh(d, a, b, c, x[12], S32, 0xe6db99e5)  # 46
    c = fn_hh(c, d, a, b, x[15], S33, 0x1fa27cf8)  # 47
    b = fn_hh(b, c, d, a, x[2], S34, 0xc4ac5665)  # 48

    # Round 4
    a = fn_ii(a, b, c, d, x[0], S41, 0xf4292244)  # 49
    d = fn_ii(d, a, b, c, x[7], S42, 0x432aff97)  # 50
    c = fn_ii(c, d, a, b, x[14], S43, 0xab9423a7)  # 51
    b = fn_ii(b, c, d, a, x[5], S44, 0xfc93a039)  # 52
    a = fn_ii(a, b, c, d, x[12], S41, 0x655b59c3)  # 53
    d = fn_ii(d, a, b, c, x[3], S42, 0x8f0ccc92)  # 54
    c = fn_ii(c, d, a, b, x[10], S43, 0xffeff47d)  # 55
    b = fn_ii(b, c, d, a, x[1], S44, 0x85845dd1)  # 56
    a = fn_ii(a, b, c, d, x[8], S41, 0x6fa87e4f)  # 57
    d = fn_ii(d, a, b, c, x[15], S42, 0xfe2ce6e0)  # 58
    c = fn_ii(c, d, a, b, x[6], S43, 0xa3014314)  # 59
    b = fn_ii(b, c, d, a, x[13], S44, 0x4e0811a1)  # 60
    a = fn_ii(a, b, c, d, x[4], S41, 0xf7537e82)  # 61
    d = fn_ii(d, a, b, c, x[11], S42, 0xbd3af235)  # 62
    c = fn_ii(c, d, a, b, x[2], S43, 0x2ad7d2bb)  # 63
    b = fn_ii(b, c, d, a, x[9], S44, 0xeb86d391)  # 64

    a = uint4_add(a, state[0])
    b = uint4_add(b, state[1])
    c = uint4_add(c, state[2])
    d = uint4_add(d, state[3])

    return a, b, c, d


def uint4_add(a, b):
    return (a + b) & 0xffffffff


def fn_f(x, y, z):
    return (x & y) | (~x & z)


def fn_g(x, y, z):
    return (x & z) | (y & ~z)


def fn_h(x, y, z):
    return x ^ y ^ z


def fn_i(x, y, z):
    return (y ^ (x | ~z)) & 0xffffffff


def rotate_left(x, n):
    # the & here makes sure that bits drop off to the right
    return ((x << n & 0xffffffff) | (x >> (32-n)))


def double_fn(fn, a, b, c, d, x, s, ac):
    a += fn(b, c, d) + x + ac
    a = a & 0xffffffff
    a = rotate_left(a, s)
    a += b
    a = a & 0xffffffff
    return a


fn_ff = functools.partial(double_fn, fn_f)
fn_gg = functools.partial(double_fn, fn_g)
fn_hh = functools.partial(double_fn, fn_h)
fn_ii = functools.partial(double_fn, fn_i)


def decode(input):
    """Decodes bytes into a list 4 byte words"""
    def words(input):
        return [input[i:i+4] for i in range(0, len(input), 4)]

    return [
        word[0] | (word[1] << 8) | (word[2] << 16) | (word[3] << 24)
        for word in words(input)
    ]


def encode(input):
    """Decodes a list 4 byte words into bytes"""
    output = bytearray()
    for word in input:
        output.append(word & 0xff)
        output.append((word >> 8) & 0xff)
        output.append((word >> 16) & 0xff)
        output.append((word >> 24) & 0xff)
    return bytes(output)


def main():
    parser = argparse.ArgumentParser(description='Demonstrate md5 length '
                                     'extension attacks.')
    parser.add_argument('--mac', type=str, dest='mac', required=True,
                        help='The original md5 MAC')
    parser.add_argument('--msg', type=str, dest='msg', required=True,
                        help='The original message')
    parser.add_argument('--keylen', type=int, dest='keylen', required=True,
                        help='The length of the secret key used to generate '
                        'the MAC')
    parser.add_argument('--ext', type=str, dest='ext', required=True,
                        help='The extension to append to the message')
    parser.add_argument('--out', type=str, dest='out', required=True,
                        help='The output file for the extended message')
    args = parser.parse_args()
    new_mac, tampered_msg = lenext(args.mac, args.keylen, 
                                   args.msg.encode('utf-8'), 
                                   args.ext.encode('utf-8'))
    print(new_mac)
    with open(args.out, 'wb') as f:
        f.write(tampered_msg)


if __name__ == '__main__':
    main()
