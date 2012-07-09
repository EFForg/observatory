import Crypto.Cipher
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto import Random
import hashlib
import hmac as HMAC
import datetime
import dateutil.parser
import math
import struct
import operator

class CryptoException(Exception):
    "All exceptions throw intentionally from this module"
    pass

def Hash(alg, data):
    "Hash the data according to the given algorithm.  Example algorithm: 'SHA1'"
    h = hashlib.new(alg)
    h.update(data)
    return h.digest()

def get_date(offset=0):
    "Get the current date/time, offset by the number of days specified, with second precision"
    n = datetime.datetime.utcnow()
    if offset:
        n += datetime.timedelta(offset)
    return n

def fmt_date(d):
    "Generate an ISO8601-formatted date from a datetime"
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_date(d):
    "Parse a string containing an ISO8601 date into a datetime"
    return dateutil.parser.parse(d, ignoretz=True)

def b64(s):
    "Base64 encode, without newlines"
    return s.encode('base64').replace('\n', '')

def b64d(s):
    "Base64 decode"
    return s.decode('base64')

def b64_to_long(b):
    "Turn a base64-encoded byte array into a long"
    return bytes_to_long(b64d(b))

def long_to_b64(l):    
    "Turn a long into a base64-encoded byte array"
    return b64(long_to_bytes(l))

__algorithms__ = {
    "AES-256-CBC": (Crypto.Cipher.AES, 256 / 8, Crypto.Cipher.AES.MODE_CBC),
    "AES-128-CBC": (Crypto.Cipher.AES, 128 / 8, Crypto.Cipher.AES.MODE_CBC),
    "HMAC-SHA1":   (hashlib.sha1, 64, None),
    "HMAC-SHA256": (hashlib.sha256, 64, None),
}

def getAlgorithm(algorithm):
    "Get am implementation of a crypto algorithm by name"
    ret = __algorithms__.get(algorithm, None)
    if not ret:
        raise CryptoException("Unknown algorithm: " + algorithm)
    return ret

def pad(data, k):
    # See RFC 5652 Section 6.3
    v = k - (len(data) % k)
    return data + (chr(v) * v)

def unpad(data):
    # See RFC 5652 Section 6.3
    s = ord(data[-1])
    return data[:-s]

def pad_1_5(msg, k):
    "PKCS1-1.5 padding to k octets"
    if len(msg) > (k - 11):
        raise CryptoException("Message too long, max=" + str(k - 11) + " actual: " + str(len(msg)))
    # rfc3447, section 7.2.1
    pslen = k - len(msg) - 3
    ps = generateRandomNonZero(pslen)
    return "\x00\x02" + ps + "\x00" + msg

def unpad_1_5(msg):
    "PKCS1-1.5 unpadding"
    if msg[0:2] == '\x00\x02':
        offset = msg.find("\x00", 2)
        if offset<2:
            raise CryptoException("Invalid padding (no zero)")
        return msg[offset+1:]
    if msg[0] == "\x02":
        offset = msg.find("\x00", 1)
        if offset<2:
            raise CryptoException("Invalid padding (no zero)")
        return msg[offset+1:]
        
    raise CryptoException("Invalid padding prefix (perhaps invalid decryption?): " + repr(msg))

# rfc3447#appendix-B.2.1
def MGF1_sha1(mgfSeed, maskLen):
    "MGF1 mask generation function"
    hLen = 20
    # Huh?
    # If maskLen > 2^32 hLen, output "mask too long" and stop.
    T = ""
    for counter in range(0,int(math.ceil(float(maskLen) / float(hLen)))):
        C = struct.pack("!I", counter)
        T += hashlib.sha1(mgfSeed + C).digest()
    return T[:maskLen]

# rfc 3447, section 7.1.1
def pad_oaep_sha1(msg, k):
    hLen = 20
    L = ""
    mLen = len(msg)
    if mLen > (k - 2*hLen - 2):
        raise CryptoException("Message too long, max=" + str(k - 2*hLen - 2) + " actual: " + str(mLen))
    lHash = hashlib.sha1(L).digest()
    PS = "\x00" * (k - mLen - 2*hLen - 2)
    DB = lHash + PS + "\x01" + msg
    seed = generateRandom(hLen)
    dbMask = MGF1_sha1(seed, k - hLen - 1)
    maskedDB = xors(DB, dbMask)
    seedMask = MGF1_sha1(maskedDB, hLen)
    maskedSeed = xors(seed, seedMask)
    return "\x00" + maskedSeed + maskedDB

# rfc 3447, section 7.1.2
def unpad_oaep_sha1(EM, k):
    hLen = 20
    maskedSeed = EM[1:1+hLen]
    maskedDB = EM[1+hLen:]
    seedMask = MGF1_sha1(maskedDB, hLen)
    seed = xors(maskedSeed, seedMask)
    dbMask = MGF1_sha1(seed, k - hLen - 1)
    DB = xors(maskedDB, dbMask)
    i = hLen
    while DB[i] == "\x00":
        i += 1
    if DB[i] != "\x01":
        raise CryptoException("Bad OAEP padding")
    return DB[i+1:]

def symmetricEncrypt(key, iv, algorithm, data):
    (alg, size, mode) = getAlgorithm(algorithm)
    assert(len(key) == size)
    assert(len(iv) == alg.block_size)
    cipher = alg.new(key, mode, iv)
    return cipher.encrypt(pad(data, alg.block_size))

def symmetricDecrypt(key, iv, algorithm, data):
    (alg, size, mode) = getAlgorithm(algorithm)
    assert(len(key) == size)
    cipher = alg.new(key, mode, iv)
    return unpad(cipher.decrypt(data))

def generateIV(algorithm):
    (alg, size, mode) = getAlgorithm(algorithm)
    return generateRandom(alg.block_size)

def generateSessionKey(algorithm):
    # account for kdf size
    (alg, size, mode) = getAlgorithm(algorithm)
    return generateRandom(size)

def hmac(key, algorithm, data):
    (alg, size, mode) = getAlgorithm(algorithm)
    h = HMAC.new(key, data, alg)
    return h.digest()

def hmac_sha1(key, data):
    h = HMAC.new(key, data, hashlib.sha1)
    return h.digest()

def hmac_sha256(key, data):
    h = HMAC.new(key, data, hashlib.sha256)
    return h.digest()

rand = Random.new()
def generateRandom(octets):
    return rand.read(octets)

def generateRandomNonZero(octets):
    r = list(rand.read(octets))
    for i in range(octets):
        if r[i] == '\x00':
            r[i] = '\x01' #ick
    return "".join(r)

def kdf(k, use, f):
    (alg, size, mode) = getAlgorithm(use)
    return f(k, use, size)

def xors(*args):
    "xor 2 or more strings, octet by octet"
    assert(len(args) > 1)
    return ''.join([chr(reduce(operator.xor, map(ord,vals))) for vals in zip(*args)])

def PBKDF2_HMAC_SHA1_1024(pw, salt, desired):
    return PBKDF2_HMAC_SHA1(pw, salt, 1024, desired)

def PBKDF2_HMAC_SHA1(pw, salt, iterations, desired):
    dkLen = desired
    hLen = 20 # len(HMAC-SHA1)
    
    if dkLen > (2**32 - 1) * hLen:
        raise CryptoException("derived key too long")

    l = int(math.ceil(float(dkLen) / float(hLen)))

    def F(P, S, c, i):
        if c < 1:
            raise CryptoException("invalid number of iterations")
        key_one = S + struct.pack("!I", i)
        prev = hmac_sha1(P, key_one)
        acc = prev
        for j in range(1,c):
            prev = hmac_sha1(P, prev)
            acc = xors(acc, prev)
        return acc

    ret = ""
    for i in range(l):
        ret += F(pw, salt, iterations, i + 1)

    return ret[:dkLen]

def AES_XCBC_MAC(K, M):
    # rfc3566, section 4
    a = Crypto.Cipher.AES.new(K)
    block = 16
    k1 = a.encrypt("\x01" * block)
    a1 = Crypto.Cipher.AES.new(k1)
    k2 = a.encrypt("\x02" * block)
    k3 = a.encrypt("\x03" * block)
    E = "\x00" * block
    numblocks = int(math.ceil(float(len(M)) / float(block)))
    for i in range(numblocks-1):
        mi = M[i*block:(i+1)*block]
        E = a1.encrypt(xors(mi, E))
    mn = M[(numblocks-1)*block:]
    if len(mn) == block:
        # If the blocksize of M[n] is 128 bits:
        # XOR M[n] with E[n-1] and Key K2, then encrypt the result with
        # Key K1, yielding E[n].
        E = a1.encrypt(xors(xors(mn, E), k2))
    else:
        # Pad M[n] with a single "1" bit, followed by the number of
        # "0" bits (possibly none) required to increase M[n]'s
        # blocksize to 128 bits.
        mn += "\x80" + ("\x00" * (block - len(mn) - 1))
        assert(len(mn) == block)
        E = a1.encrypt(xors(xors(mn, E), k3))
    return E

def P_SHA256(secret, seed, k):
    A = seed
    p = hmac_sha256(secret, A + seed)
    while len(p) < k:
        A = hmac_sha256(secret, A + seed)
        p += A
    return p[:k]

def create_rsa(n, e, private=None, p=None, q=None, u=None):
    if private:
        return RSA.construct((n, e, private, p, q, u))
    return RSA.construct((n, e))

def generate_rsa(size):
    return RSA.generate(size)

def encrypt(m, e, n):
    # m ^ e (mod n)
    return pow(m, e, n)

def decrypt(c, d, n):
    # c^d (mod n)
    return pow(c, d, n)
