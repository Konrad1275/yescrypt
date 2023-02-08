import hashlib
import hmac
from array import *
from math import floor
from struct import *
from pbkdf2 import PBKDF2

PWXSIMPLE = 2
PWXGATHER = 4
PWXROUNDS = 6
SWIDTH = 8

PWXBYTES = PWXGATHER * PWXSIMPLE * 8
PWXWORDS = PWXBYTES // 4
SBYTES = 3 * (1 << SWIDTH) * PWXSIMPLE * 8
SWORDS = SBYTES // 4
SMASK = ((1 << SWIDTH) - 1) * PWXSIMPLE * 8
RMIN = (PWXBYTES + 127) // 128

YESCRYPT_RW = 1
YESCRYPT_WORM = 2
YESCRYPT_PREHASH = 0x100000


class Sbox:
    def __init__(self, S):
        self.S = S
        self.S2 = 0
        self.S1 = SWORDS // 3
        self.S0 = (SWORDS // 3) * 2
        self.w = 0


def calculate(password, salt, N, r, p, t, g, flags, dkLen):
    if (flags & YESCRYPT_RW) != 0 and N // p <= 1:
        raise Exception("YESCRYPT_RW wymaga N/p >= 2")

    if (flags & YESCRYPT_RW) != 0 and p >= 1 and N // p >= 0x100 and N // p * r >= 0x20000:
        password = calculate(password, salt, N >> 6, r, p, 0, 0, flags | YESCRYPT_PREHASH, 32)
    for i in range(0, g + 1):
        if i == g:
            dklen_g = dkLen
        else:
            dklen_g = 32
        password = yescrypt_kdf_body(password, salt, N, r, p, t, flags, dklen_g)
        N <<= 2
        t >>= 1

    return password


def yescrypt_kdf_body(password, salt, N, r, p, t, flags, dkLen):
    if flags != 0:
        key = "yescrypt"
        if (flags & YESCRYPT_PREHASH) != 0:
            key += "-prehash"
        password = hmac_sha256(key, password)

    bbytes = pbkdf2_sha256(password, salt, 1, p * 128 * r)
    B = array('L', unpack('I' * (len(bbytes) // 4), bbytes))

    if flags != 0:
        password = bytearray(32)
        for i in range(0, 32):
            password[i] = bbytes[i]

    if (flags & YESCRYPT_RW) != 0:
        sMix(N, r, t, p, B, flags, password)
    else:
        for i in range(0, p):
            Bi = B[i * 2 * r * 16: i * 2 * r * 16 + 2 * r * 16]
            sMix(N, r, t, 1, Bi, flags, password)
            B[i * 2 * r * 16: i * 2 * r * 16 + 2 * r * 16] = Bi

    # bbytes = ''.join(pack('I', b) for b in B)
    result = pbkdf2_sha256(password, bbytes, 1, max(dkLen, 32))

    if (flags & (YESCRYPT_RW | YESCRYPT_WORM)) != 0 and (flags & YESCRYPT_PREHASH) == 0:
        clientValue = result[0:32]
        clientKey = hmac_sha256(clientValue, "Client Key")
        storedKey = sha256(clientKey)

        for i in range(0, 32):
            result[i] = storedKey[i]

    return result[0:dkLen]


def sMix(N, r, t, p, blocks, flags, sha255):
    sboxes = []
    for i in range(0, p):
        sboxes.append(Sbox(array('L', [0] * SWORDS)))

    n = N // p
    Nloop_all = fNloop(n, t, flags)

    Nloop_rw = 0
    if (flags & YESCRYPT_RW) != 0:
        Nloop_rw = Nloop_all // p

    n = n - (n % 2)

    Nloop_all = Nloop_all + (Nloop_all % 2)
    Nloop_rw += 1
    Nloop_rw = Nloop_rw - (Nloop_rw % 2)

    V = [0]*N*2*r*16

    for i in range(0, p):
        v = i * n
        if i == p - 1:
            n = N - v

        if (flags & YESCRYPT_RW) != 0:
            twocells = blocks[i * 2 * r * 16: i * 2 * r * 16 + 32]
            sMix1(1, twocells, SBYTES // 128, sboxes[i].S, flags & ~YESCRYPT_RW, None)
            blocks[i * 2 * r * 16: i * 2 * r * 16 + 32] = twocells

            if i == 0:
                sha256_new = hmac_sha256(blocks[16 * i + 2 * r - 2], sha255)
                for j in range(0, 32):
                    sha255[j] = sha256_new[j]
        else:
            sboxes[i] = None

        BlockI = blocks[i * 2 * r * 16: i * 2 * r * 16 + 2 * r * 16]
        VPart = V[v * 2 * r * 16: v * 2 * r * 16 + n * 2 * r * 16]
        sMix1(r, BlockI, n, VPart, flags, sboxes[i])
        sMix2(r, BlockI, p2floor(n), Nloop_rw, VPart, flags, sboxes[i])
        blocks[i * 2 * r * 16: i * 2 * r * 16 + 2 * r * 16] = BlockI
        V[v * 2 * r * 16: v * 2 * r * 16 + n * 2 * r * 16] = VPart

    for i in range(0, p):
        BlockI = blocks[i * 2 * r * 16: i * 2 * r * 16 + 2 * r * 16]
        sMix2(r, BlockI, N, Nloop_all - Nloop_rw, V, flags & ~YESCRYPT_RW, sboxes[i])
        blocks[i * 2 * r * 16: i * 2 * r * 16 + 2 * r * 16] = BlockI


def sMix1(r, block, N, outputblocks, flags, sbox):
    simd_shuffle_block(2 * r, block)

    for i in range(0, N):
        for j in range(0, 2 * r * 16):
            outputblocks[i * 2 * r * 16 + j] = block[j]
        if (flags & YESCRYPT_RW) != 0 and i > 1:
            j = wrap(integerify(r, block), i)
            for k in range(0, 2 * r * 16):
                block[k] ^= outputblocks[j * 2 * r * 16 + k]

        if sbox is None:
            blockmix_salsa8(r, block)
        else:
            blockmix_pwxform(r, block, sbox)

    simd_unshuffle_block(2 * r, block)


def sMix2(r, block, N, Nloop, outputblocks, flags, sbox):
    simd_shuffle_block(2 * r, block)

    for i in range(0, Nloop):

        j = integerify(r, block) & (N - 1)

        for k in range(0, 2 * r * 16):
            block[k] ^= outputblocks[j * 2 * r * 16 + k]

        if (flags & YESCRYPT_RW) != 0:
            for k in range(0, 2 * r * 16):
                outputblocks[j * 2 * r * 16 + k] = block[k]

        if sbox is None:
            blockmix_salsa8(r, block)
        else:
            blockmix_pwxform(r, block, sbox)

    simd_unshuffle_block(2 * r, block)


def blockmix_pwxform(r, block, sbox):
    pwx_blocks = (2 * r * 16) // PWXWORDS

    X = [0]*PWXWORDS
    for i in range(0, PWXWORDS):
        X[PWXWORDS - i - 1] = block[len(block) - i - 1]

    for i in range(0, pwx_blocks):
        if pwx_blocks > 1:
            for j in range(0, PWXWORDS):
                X[j] ^= block[i * PWXWORDS + j]

        pwxform(X, sbox)

        for j in range(0, PWXWORDS):
            block[i * PWXWORDS + j] = X[j]

    i = (pwx_blocks - 1) * PWXWORDS // 16
    bi = block[i * 16: (i * 16) + 16]
    salsa20(bi, 2)
    for j in range(0, 16):
        block[i * 16 + j] = bi[j]

    i = i + 1
    while i < 2 * r:
        for j in range(0, 16):
            block[i * 16 + j] ^= block[(i - 1) * 16 + j]

        bi = block[i * 16: (i * 16) + 16]
        salsa20(bi, 2)
        for j in range(0, 16):
            block[i * 16 + j] = bi[j]

        i += 1


def pwxform(PWXBlock, SBox):
    S0 = SBox.S0
    S1 = SBox.S1
    S2 = SBox.S2
    for i in range(0, PWXROUNDS):
        for j in range(0, PWXGATHER):
            x_lo = PWXBlock[2 * j * PWXSIMPLE]
            x_hi = PWXBlock[2 * j * PWXSIMPLE + 1]
            p0 = (x_lo & SMASK) / (PWXSIMPLE * 8)
            p1 = (x_hi & SMASK) / (PWXSIMPLE * 8)
            for k in range(0, PWXSIMPLE):
                lo = PWXBlock[2 * (j * PWXSIMPLE + k)]
                hi = PWXBlock[2 * (j * PWXSIMPLE + k) + 1]
                s0 = SBox.S[int(S0 + 2 * (p0 * PWXSIMPLE + k))] + (SBox.S[int(S0 + 2 * (p0 + PWXSIMPLE + k) + 1)] * 1 << 32)
                s1 = SBox.S[int(S1 + 2 * (p1 * PWXSIMPLE + k))] + (SBox.S[int(S1 + 2 * (p1 * PWXSIMPLE + k) + 1)] * 1 << 32)
                result = (((hi * lo) + s0) ^ s1) % (1 << 64)
                PWXBlock[2 * (j * PWXSIMPLE + k)] = result % (1 << 32)
                PWXBlock[2 * (j * PWXSIMPLE + k)] = floor(result // (1 << 32))
                if i != 0 and i != PWXROUNDS - 1:
                    SBox.S[S2 + 2 * SBox.w] = result % (1 << 32)
                    SBox.S[S2 + 2 * SBox.w + 1] = floor(result // (1 << 32))
                    SBox.w = SBox.w + 1
    SBox.S0 = S2
    SBox.S1 = S0
    SBox.S2 = S1
    SBox.w = SBox.w & (SMASK // 8)


def blockmix_salsa8(r, block):
    X = array('L', [0] * 16)
    for i in range(0, 16):
        X[i] = block[16 * (2 * r - 1) + i]
    # X = block[2 * r - 1]
    Y = [0]*16*2*r
    for i in range(0, 2 * r):
        for j in range(0, 16):
            X[j] ^= block[i * 16 + j]
        salsa20(X, 8)
        if i % 2 == 0:
            for j in range(0, 16):
                Y[i // 2 * 16 + j] = X[j]
        else:
            for j in range(0, 16):
                Y[(r + (i - 1) // 2) * 16 + j] = X[j]

    for i in range(0, 2 * r * 16):
        block[i] = Y[i]


def salsa20(B, rounds):
    simd_unshuffle_block(1, B)

    x = []
    from numpy.compat import long
    for i in range(0, len(B)):
        x.append(long(B[i]))

    for i in range(rounds, 0, -2):
        a = (x[0] + x[12]) & 0xffffffff
        x[4] ^= ((a << 7) | (a >> 25))
        a = (x[4] + x[0]) & 0xffffffff
        x[8] ^= ((a << 9) | (a >> 23))
        a = (x[8] + x[4]) & 0xffffffff
        x[12] ^= ((a << 13) | (a >> 19))
        a = (x[12] + x[8]) & 0xffffffff
        x[0] ^= ((a << 18) | (a >> 14))
        a = (x[5] + x[1]) & 0xffffffff
        x[9] ^= ((a << 7) | (a >> 25))
        a = (x[9] + x[5]) & 0xffffffff
        x[13] ^= ((a << 9) | (a >> 23))
        a = (x[13] + x[9]) & 0xffffffff
        x[1] ^= ((a << 13) | (a >> 19))
        a = (x[1] + x[13]) & 0xffffffff
        x[5] ^= ((a << 18) | (a >> 14))
        a = (x[10] + x[6]) & 0xffffffff
        x[14] ^= ((a << 7) | (a >> 25))
        a = (x[14] + x[10]) & 0xffffffff
        x[2] ^= ((a << 9) | (a >> 23))
        a = (x[2] + x[14]) & 0xffffffff
        x[6] ^= ((a << 13) | (a >> 19))
        a = (x[6] + x[2]) & 0xffffffff
        x[10] ^= ((a << 18) | (a >> 14))
        a = (x[15] + x[11]) & 0xffffffff
        x[3] ^= ((a << 7) | (a >> 25))
        a = (x[3] + x[15]) & 0xffffffff
        x[7] ^= ((a << 9) | (a >> 23))
        a = (x[7] + x[3]) & 0xffffffff
        x[11] ^= ((a << 13) | (a >> 19))
        a = (x[11] + x[7]) & 0xffffffff
        x[15] ^= ((a << 18) | (a >> 14))
        a = (x[0] + x[3]) & 0xffffffff
        x[1] ^= ((a << 7) | (a >> 25))
        a = (x[1] + x[0]) & 0xffffffff
        x[2] ^= ((a << 9) | (a >> 23))
        a = (x[2] + x[1]) & 0xffffffff
        x[3] ^= ((a << 13) | (a >> 19))
        a = (x[3] + x[2]) & 0xffffffff
        x[0] ^= ((a << 18) | (a >> 14))
        a = (x[5] + x[4]) & 0xffffffff
        x[6] ^= ((a << 7) | (a >> 25))
        a = (x[6] + x[5]) & 0xffffffff
        x[7] ^= ((a << 9) | (a >> 23))
        a = (x[7] + x[6]) & 0xffffffff
        x[4] ^= ((a << 13) | (a >> 19))
        a = (x[4] + x[7]) & 0xffffffff
        x[5] ^= ((a << 18) | (a >> 14))
        a = (x[10] + x[9]) & 0xffffffff
        x[11] ^= ((a << 7) | (a >> 25))
        a = (x[11] + x[10]) & 0xffffffff
        x[8] ^= ((a << 9) | (a >> 23))
        a = (x[8] + x[11]) & 0xffffffff
        x[9] ^= ((a << 13) | (a >> 19))
        a = (x[9] + x[8]) & 0xffffffff
        x[10] ^= ((a << 18) | (a >> 14))
        a = (x[15] + x[14]) & 0xffffffff
        x[12] ^= ((a << 7) | (a >> 25))
        a = (x[12] + x[15]) & 0xffffffff
        x[13] ^= ((a << 9) | (a >> 23))
        a = (x[13] + x[12]) & 0xffffffff
        x[14] ^= ((a << 13) | (a >> 19))
        a = (x[14] + x[13]) & 0xffffffff
        x[15] ^= ((a << 18) | (a >> 14))

    for i in range(0, 16):
        B[i] = (B[i] + x[i]) & 0xffffffff

    simd_shuffle_block(1, B)


def simd_shuffle_block(twiceR, block):
    saved = [0]*16
    for i in range(0, twiceR):
        for j in range(0, 16):
            saved[j] = block[i * 16 + (j * 5) % 16]
        for j in range(0, 16):
            block[i * 16 + j] = saved[(j*5) % 16]


def simd_unshuffle_block(twiceR, block):
    saved = [0]*16
    for i in range(0, twiceR):
        for j in range(0, 16):
            saved[j] = block[i * 16 + j]
        for j in range(0, 16):
            block[i * 16 + (j * 5) % 16] = saved[j]


def integerify(R, Block):
    return Block[16 * (2 * R - 1)] + (Block[16 * (2 * R - 1) + 13] * (1 << 32))


def fNloop(n, t, flags):
    if (flags & YESCRYPT_RW) != 0:
        if t == 0:
            return (n + 2) // 3
        elif t == 1:
            return (2 * n + 2) // 3
        else:
            return (t - 1) * n
    elif (flags & YESCRYPT_WORM) != 0:
        if t == 0:
            return n
        elif t == 1:
            return n + (n + 1) // 2
        else:
            return t * n
    else:
        return n


def p2floor(x):
    y = x & (x - 1)
    while y != 0:
        x = y
        y = x & (x - 1)
    return x


def wrap(X, L):
    n = p2floor(L)
    return (X % n) + (L - n)


def sha256(message):
    m = hashlib.sha256()
    m.update(str(message).encode())
    return bytearray(m.digest())


def hmac_sha256(key, message):
    key1 = str(key)
    return bytearray(hmac.new(bytes(key1.encode()), msg=str(message).encode(), digestmod=hashlib.sha256).digest())


class mysha256:
    digest_size = 32

    @staticmethod
    def new(inp=''):
        return hashlib.sha256(inp)


def pbkdf2_sha256(password, salt, count, length):
    return bytearray(PBKDF2(str(password), str(salt), count, mysha256()).read(length))
