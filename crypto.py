from crypto_utils import *
import json
import hashlib
import sys

version = "1.0"
JSON_MIME = "application/json"
ca_bundle = []

def set_bundle(b):
    global ca_bundle
    for c in b:
        if c.Type != "certificate":
            raise CryptoException("Invalid bundle")
    ca_bundle = b

def _JSONdefault(o):
    """Turn an object into JSON.  
    Dates and instances of classes derived from CryptoTyped get special handling"""
    if isinstance(o, datetime.datetime):
        return fmt_date(o)
    return o.JSON()

def JSONdumps(o, indent=None):
    "Dump crypto objects to string"
    return json.dumps(o, default=_JSONdefault, indent=indent, sort_keys=True)

def JSONwrite(o, fp=None, indent=None):
    def wj(p):
        r = json.dump(o, p, default=_JSONdefault, indent=indent, sort_keys=True)
        if indent:
            p.write("\n")
        return r

    if not fp:
        return wj(sys.stdout)
    elif isinstance(fp, basestring):
        f = open(fp, "w")
        r = wj(f)
        f.close()
        return r
    else:
        return wj(fp)

def _JSONobj(d):
    "Turn a JSON dictionary into a crypto object"
    t = d.get("Type", None)
    if t:
        return TypeName.create(t, d)
    return d

def JSONloads(s):
    "Load a string as a JSON object, converting to crypto objects as needed"
    return json.loads(s, object_hook=_JSONobj)

def get_kdf(name):
    kdf_f = {"P_SHA256": P_SHA256,
             "PBKDF2_HMAC_SHA1": PBKDF2_HMAC_SHA1_1024}.get(name)
    if not kdf_f:
        raise CryptoException("Unknown KDF: %s" % name)
    return kdf_f

class CoDec(object):
    """Abstract static class for encoding and decoding from JSON versions.  
By default, does identity operations."""

    @classmethod
    def schema(cls):
        return {"type": "string"}

    @classmethod
    def encode(cls, x):
        return x

    @classmethod
    def decode(cls, x):
        return x

class Identity(CoDec):
    """It feels more natural to call this 'Identity' when it is being used directly."""
    pass
    
class Base64codec(CoDec):
    @classmethod
    def schema(cls):
        return {"type": "string",
                "format": "base64"}

    @classmethod
    def encode(cls, x):
        return b64(x)

    @classmethod
    def decode(cls, x):
        return b64d(x)

class DateCodec(CoDec):
    @classmethod
    def schema(cls):
        return {"type": "string",
                "format": "date-time"}

    @classmethod
    def encode(cls, x):
        return fmt_date(x)

    @classmethod
    def decode(cls, x):
        return parse_date(x)

class LongCodec(CoDec):
    @classmethod
    def encode(cls, x):
        return long_to_b64(x)

    @classmethod
    def decode(cls, x):
        return b64_to_long(x)

class ListCodec(CoDec):
    lst = []
    @classmethod
    def schema(cls):
        return {"type": "string",
                "enum": cls.lst}

class TypeName(object):
    """A decorator that tells the framework what the Type of the class
is.  This information is used both for selecting the right class at
de-serialization time as well as writing out the Type at serialization time."""
    typeMap = {}
    
    def __init__(self, Type):
        self.typ = Type

    def __call__(self, cls):
        TypeName.typeMap[self.typ] = cls
        cls.Type = self.typ
        return cls

    @classmethod
    def create(cls, name, json):
        cons = TypeName.typeMap.get(name, None)
        if not cons:
            return name
        return cons(json=json)

class Props(object):
    """A decorator that adds a JSON access property for each of the strings that are passed.
Each property can have a type of plain, date, base64, or long.  Types
other than plain cause encoding to happen on set, and decoding to
happen on get.  The default type is plain."""
    def __init__(self, *args, **kwargs):
        self.map = dict.fromkeys(args, Identity())
        self.map.update(kwargs)
        for prop, typ in self.map.iteritems():
            if isinstance(typ, list):
                self.map[prop] = type("ListCodec_" + "_".join(typ), (ListCodec,), {"lst": typ})

    def __call__(self, cls):
        cls.Props = self.map.keys()
        for prop,typ in self.map.iteritems():
            def prop_getter(self, p=prop, codec=typ):
                return codec.decode(self.json_.get(p))
            def prop_setter(self, x, p=prop, codec=typ):
                self.json_[p] = codec.encode(x)
            def prop_deleter(self, p=prop):
                del self.json_[p]
            setattr(cls, prop, property(prop_getter, prop_setter, prop_deleter))
        cls.PropMap = self.map
            
        return cls

@Props("Type")
class CryptoTyped(Identity):
    """The base class for all top-level crypto objects.  Crypto
    objects contain a dictionary that holds their state in a form easy
    to be translated to JSON.  Getters and setters modify the JSON
    dictionary."""
    def __init__(self, json=None):
        super(CryptoTyped,self).__init__()
        if json:
            self.json_ = json
        else:
            self.json_ = {"Type": self.Type}

    def JSON(self):
        return self.json_

    @property
    def JSONstr(self):
        return JSONdumps(self.json_)

    @property
    def Base64(self):
        return b64(JSONdumps(self.json_))

    def __cmp__(self, other):
        if self.__class__ != other.__class__:
            return -1
        r = cmp(self.json_["Type"], other.json_["Type"])
        if r:
            return r

        for p in self.Props:
            x = getattr(self, p, None)
            y = getattr(other, p, None)
                
            # arrays should do this by default, if you ask me
            if isinstance(x, (list, tuple)):
                r = cmp(len(x), len(y))
                if r:
                    return r
                for (xn, yn) in zip(x, y):
                    r = cmp(xn, yn)
                    if r:
                        return r
            else:
                r = cmp(x, y)
                if r:
                    return r
        return 0

    def __str__(self):
        return JSONdumps(self.json_, indent=2)

    @classmethod
    def schema(cls):
        "Return the schema for this class"
        props = {}
        
        for p in cls.Props:
            t = cls.PropMap[p]
            props[p] = t.schema()
        props["Type"] = {"type" : "string",
                         "enum" : [cls.__name__]}
        s = {"type" : "object",
             "properties" : props}
        return s

@Props("Version")
class CryptoVersioned(CryptoTyped):
    def __init__(self, json=None, ver=version):
        super(CryptoVersioned, self).__init__(json)
        if json:
            if json.get("Version", None) != ver:
                raise CryptoException("Invalid version")
        else:
            self.json_["Version"] = ver

    def __cmp__(self, other):
        r = super(CryptoVersioned, self).__cmp__(other)
        if r:
            return r
        r = cmp(self.Version, other.Version)
        if r:
            return r

        return 0

    def write(self, fp=None, indent=None):
        JSONwrite(self, fp, indent)

    @classmethod
    def read(cls, fp):
        """Read all data from the given file name or file-like object pointer.  
Closes the file handle when complete."""
        def rj(p):
            data = json.load(p, object_hook=_JSONobj)
            p.close()
            return data

        if isinstance(fp, basestring):
            f = open(fp, "r")
            return rj(f)
        else:
            return rj(fp)

    def wrapSign(self, ca_priv, ca_cert):
        s = Signed(self.JSONstr, JSON_MIME)
        s.sign(ca_priv, ca_cert)
        return s

    def wrapEncrypt(self, key):
        e = Encrypted(self.JSONstr, JSON_MIME)
        e.encrypt(key=key)
        return e

@Props("Name", "Value")
@TypeName("extension")
class CertificateExtension(CryptoTyped):
    known_extensions = {}
    
    def __init__(self, name=None, value=None, json=None):
        super(CertificateExtension, self).__init__(json)
        if name:
            self.Name = name
        if value:
            self.Value = value
            
    def cannon(self):
        return self.Name.encode('utf8') + "\x00" + self.Value.encode('utf8')

    def check(self, cert):
        n = self.known_extensions.get(self.Name)
        if not n:
            return False
        return n(self, cert)
        
@Props("Name", "PublicKey", "Hash", "Serial", "Extensions", "CriticalExtensions", NotBefore=DateCodec, NotAfter=DateCodec)
@TypeName("certificate")
class Certificate(CryptoVersioned):
    def __init__(self, name=None, pubkey=None, serial=None, 
                 validityDays=None, notBefore=None, notAfter=None,
                 json=None):
        super(Certificate, self).__init__(json)

        if name:
            self.Name = name
        if pubkey:
            self.PublicKey = pubkey

        if validityDays:
            self.NotBefore = get_date()
            self.NotAfter = get_date(validityDays)
        if notBefore:
            self.NotBefore = notBefore
        if notAfter:
            self.NotAfter = notAfter

        if serial is not None:
            self.Serial = serial
        if "Serial" not in self.json_:
            self.Serial = 0
        if "Hash" not in self.json_:
            self.Hash = self.hash()
        else:
            if self.Hash != self.hash():
                raise CryptoException("Invalid certificate hash")

    def addExtension(self, name, value):
        if "Extensions" not in self.json_:
            self.Extensions = []
        self.Extensions.append(CertificateExtension(name, value))

    def addCriticalExtension(self, name, value):
        if "CriticalExtensions" not in self.json_:
            self.CriticalExtensions = []
        self.CriticalExtensions.append(CertificateExtension(name, value))
        
    def validate(self):
        n = datetime.datetime.utcnow()
        if self.NotBefore > n:
            return False
        if self.NotAfter < n:
            return False
        if len(self.Name) == 0:
            return False
        if not self.PublicKey:
            return False
        if self.json_['Version'] != version:
            return False
        ce = self.CriticalExtensions
        if ce:
            for e in ce:
                if not e.check(self):
                    return False
        return True

    def hash(self):
        pk = self.PublicKey        
        source = [pk.Algorithm, self.Name,
                  self.json_["NotAfter"], self.json_["NotBefore"],
                  unicode(self.Serial)]
        source = [s.encode('utf8') for s in source]
        source += [long_to_bytes(pk.Exponent), long_to_bytes(pk.Modulus)]
        if "CriticalExtensions" in self.json_:
            source += [e.cannon() for e in self.CriticalExtensions]
        if "Extensions" in self.json_:
            source += [e.cannon() for e in self.Extensions]

        source = "\x00".join(source)
        return b64(hashlib.sha1(source).digest())

    def readable_hash(self):
        dig = b64d(self.Hash).encode('hex')
        f = []
        for i in range(len(dig) / 2):
            f.append(dig[i*2:(i+1)*2])
        return ":".join(f)
        
@Props(Algorithm=["RSA-PKCS1-1.5"], Exponent=LongCodec, Modulus=LongCodec)
@TypeName("publickey")
class PublicKey(CryptoTyped):
    def __init__(self, key=None, json=None):
        super(PublicKey, self).__init__(json)
        if key:
            self.key = key
            self.Exponent = key.e
            self.Modulus = key.n
            self.Algorithm = "RSA-PKCS1-1.5"
        else:
            n = self.Modulus
            e = self.Exponent
            self.key = create_rsa(n, e)

    def verify(self, signed_data, signature, signature_algorithm="RSA-PKCS1-1.5", digest_algorithm="SHA1"):
        dig = Hash(digest_algorithm, signed_data)
        if signature_algorithm != "RSA-PKCS1-1.5":
            raise CryptoException("Unknown signature algorithm")
        return self.key.verify(dig, (signature, 1))

    def encrypt(self, plaintext):
        # size is keysize_in_bits-1 for some reason.
        padded = pad_1_5(plaintext, (self.key.size() + 1)/8)
        ret = self.key.encrypt(padded, None)
        return ret[0]

    def genCertificate(self, name, validityDays=365):
        return Certificate(name=name, pubkey=self, validityDays=validityDays)

@Props("PublicKey", Algorithm=["RSA-PKCS1-1.5"], PrivateExponent=LongCodec, Prime1=LongCodec, Prime2=LongCodec, Exponent1=LongCodec, Exponent2=LongCodec, Coefficient=LongCodec)
@TypeName("privatekey")
class PrivateKey(CryptoVersioned):
    def __init__(self, key=None, size=1024, json=None):
        super(PrivateKey, self).__init__(json)
        if not json:
            if key:
                self.key = key
            else:
                self.key = generate_rsa(size)
            assert(self.key)
            self.PublicKey = PublicKey(key=self.key.publickey())
            self.PrivateExponent = self.key.d
            self.Prime1 = self.key.p
            self.Prime2 = self.key.q
            self.Exponent1 = self.key.d % (self.key.p - 1)
            self.Exponent2 = self.key.d % (self.key.q - 1)
            self.Coefficient = self.key.u
            self.Algorithm = "RSA-PKCS1-1.5"
        else:
            self.key = create_rsa(self.PublicKey.key.n, 
                                  self.PublicKey.key.e,
                                  self.PrivateExponent,
                                  self.Prime1,
                                  self.Prime2,
                                  self.Coefficient)

    def sign(self, signed_data, digest_algorithm="SHA1"):
        dig = Hash(digest_algorithm, signed_data)
        return self.key.sign(dig, None)[0]

    def decrypt(self, ciphertext):
        plain = self.key.decrypt(ciphertext)
        return unpad_1_5(plain)

def check_ca(signed):
    "Check if this block was signed by a trusted CA"
    global ca_bundle
    if not ca_bundle:
        sys.stderr.write("WARNING: no CA checks!\n")
        return True
    cert = signed.Signature.Certificate
    for c in ca_bundle:
        if cert == c:
            return c.validate()
    return False

def check_cert(cert, trusted=False):
    if not cert:
        raise CryptoException("Certificate required")
    incert = cert
    while incert.Type == "signed":
        if not trusted:
            trusted = check_ca(incert)
        if not incert.verify(trusted):
            raise CryptoException("Invalid signature")
        incert = incert.getInnerJSON()

    if not trusted:
        raise CryptoException("Not signed by a trusted CA")
    if incert.Type != "certificate":
        raise CryptoException("Not a certificate")
    if not incert.validate():
        raise CryptoException("Invalid certificate")
    return incert

@Props("Signer", SignatureAlgorithm=["RSA-PKCS1-1.5"], Value=LongCodec, Certificate=Certificate, DigestAlgorithm=["SHA1"])
@TypeName("signature")
class Signature(CryptoTyped):
    def __init__(self, cert=None, signer=None, digest_algorithm=None, sig_algorithm=None, value=None, json=None):
        super(Signature, self).__init__(json)
        if cert:
            self.Certificate = cert
        if signer:
            self.Signer = signer
        if digest_algorithm:
            self.DigestAlgorithm = digest_algorithm
        if sig_algorithm:
            self.SignatureAlgorithm = sig_algorithm
        if value:
            self.Value = value

    def verify(self, data, trust_certs):
        cert = check_cert(self.Certificate, trust_certs)

        if cert.Name != self.Signer:
            return False

        return cert.PublicKey.verify(data, self.Value, self.SignatureAlgorithm, self.DigestAlgorithm)

@Props(Signature=Signature, SignedData=Base64codec)
@TypeName("signed")
class Signed(CryptoVersioned):
    def __init__(self, data=None, contentType="text/plain", name=None, json=None):
        super(Signed, self).__init__(json)
        if data:
            if not contentType:
                raise CryptoException("Must supply content type with data")
            inner = Content(data, contentType, name=name)
            self.SignedData = JSONdumps(inner)

    def sign(self, key, cert, digest_algorithm="SHA1"):
        val = key.sign(self.SignedData, digest_algorithm)
        incert = check_cert(cert, True)

        if incert.PublicKey != key.PublicKey:
            raise CryptoException("Cert doesn't match key")

        self.Signature = Signature(cert, incert.Name, digest_algorithm, key.Algorithm, val)

    def verify(self, trust_certs=False):
        # TODO: check dates, nonces, etc?
        return self.Signature.verify(self.SignedData, trust_certs)

    def getInnerJSON(self):
        inner = JSONloads(self.SignedData)
        if inner.ContentType != JSON_MIME:
            raise CryptoException("Invalid data type, '%s' != '%s'" % (inner.ContentType, JSON_MIME))
        js = JSONloads(inner.Data)
        return js

@Props("Name", "CertificateHash", EncryptionAlgorithm=["RSA-PKCS1-1.5"], EncryptionKey=Base64codec)
@TypeName("recipient")
class Recipient(CryptoTyped):
    def __init__(self, cert=None, key=None, json=None):
        super(Recipient, self).__init__(json)
        if cert:
            self.EncryptionAlgorithm = cert.PublicKey.Algorithm
            self.CertificateHash = cert.Hash
            self.Name = cert.Name
        if key:
            self.EncryptionKey = key

@Props(Algorithm=["AES-128-CBC", "AES-256-CBC", "AES-128-GCM", "AES-256-GCM"], KDF=["P_SHA256", "PBKDF2_HMAC_SHA1"], IV=Base64codec)
@TypeName("encryption")
class Encryption(CryptoTyped):
    def __init__(self, algorithm=None, iv=None, kdf=None, json=None):
        super(Encryption, self).__init__(json)
        if algorithm:
            self.Algorithm = algorithm
        if iv:
            self.IV = iv
        if kdf:
            self.KDF = kdf

@Props(Algorithm=["HMAC-SHA1"], KDF=["P_SHA256", "PBKDF2_HMAC_SHA1"], Value=Base64codec)
@TypeName("integrity")
class Integrity(CryptoTyped):
    def __init__(self, algorithm=None, value=None, kdf=None, json=None):
        super(Integrity, self).__init__(json)
        if algorithm:
            self.Algorithm = algorithm
        if value:
            self.Value = value
        if kdf:
            self.KDF = kdf

@Props("ContentType", "Data", "Name", Date=DateCodec)
@TypeName("content")
class Content(CryptoVersioned):
    def __init__(self, data=None, contentType=None, date=None, name=None, json=None):
        super(Content, self).__init__(json)
        if data:
            self.Data = data
        if contentType:
            self.ContentType = contentType
        if name:
            self.Name = name
        if date:
            self.Date = date
        elif not json:
            self.Date = get_date()

@Props("Recipients", Encryption=Encryption, Integrity=Integrity, EncryptedData=Base64codec)
@TypeName("encrypted")
class Encrypted(CryptoVersioned):
    def __init__(self, data=None, contentType="text/plain", name=None, json=None):
        super(Encrypted, self).__init__(json)
        if data:
            if not contentType:
                raise CryptoException("Must supply content type with data")
            self.inner = Content(data, contentType, name=name)

    def encrypt(self, toCerts=None, 
                encryption_algorithm="AES-256-CBC", 
                integrity_algorithm="HMAC-SHA1", 
                key=None):
        iv = generateIV(encryption_algorithm)
        self.Encryption = Encryption(encryption_algorithm, iv=iv)

        if key:
            sk = key
            mek = kdf(sk, encryption_algorithm, PBKDF2_HMAC_SHA1_1024)
            self.Encryption.KDF = "PBKDF2_HMAC_SHA1"
        else:
            sk = generateSessionKey(encryption_algorithm)
            mek = kdf(sk, encryption_algorithm, P_SHA256)
            self.Encryption.KDF = "P_SHA256"
        js = JSONdumps(self.inner)

        ciphertext = symmetricEncrypt(mek, iv, encryption_algorithm, js)
        self.EncryptedData = ciphertext

        if toCerts:
            rcpts = []
            if not isinstance(toCerts, (list, tuple)):
                toCerts = (toCerts,)
            for c in toCerts:
                b = check_cert(c, True)
                key_exchange = b.PublicKey.encrypt(sk)
                r = Recipient(b, key_exchange)
                rcpts.append(r)
            self.Recipients = rcpts

        mik = kdf(sk, integrity_algorithm, P_SHA256)
        mac = hmac(mik, integrity_algorithm, ciphertext)
        self.Integrity = Integrity(integrity_algorithm, mac, "P_SHA256")

    def _symmetricDecrypt(self, key):
        ciphertext = self.EncryptedData
        iv = self.Encryption.IV

        encryption_algorithm = self.Encryption.Algorithm
        mek = kdf(key, encryption_algorithm, get_kdf(self.Encryption.KDF))
        plaintext = symmetricDecrypt(mek, iv, encryption_algorithm, ciphertext)
        if (not plaintext) or (len(plaintext) < 67) or (plaintext[0] != '{') or (plaintext[-1] != '}'):
            raise CryptoException("Bad decrypt: " + repr(iv) + ' ' +  repr(plaintext))
        res = JSONloads(plaintext)
        dt = res.Date
        if dt > get_date(): # TODO: clock skew
            raise CryptoException("Message from the future")

        integrity_algorithm = self.Integrity.Algorithm
        mik = kdf(key, integrity_algorithm, get_kdf(self.Integrity.KDF))
        mac = hmac(mik, integrity_algorithm, ciphertext)
        if mac != self.Integrity.Value:
            raise CryptoException("Invalid HMAC: '%s' != '%s'" % (b64(mac), b64(self.Integrity.Value)))
        return res

    def decrypt(self, privKey, cert=None, name=None, trusted=False):
        rcpt = []
        if cert:
            cert = check_cert(cert, trusted)
            h = cert.Hash
            rcpt += [r for r in self.Recipients if r.CertificateHash == h]
        if name:
            rcpt += [r for r in self.Recipients if r.Name == name]

        if not rcpt:
            raise CryptoException("Name/certificate not found in recipients")
        if len(rcpt) > 1:
            raise CryptoException("Too many matches found in recipients")
        rcpt = rcpt[0]

        ek = rcpt.EncryptionKey
        sk = privKey.decrypt(ek)
        res = self._symmetricDecrypt(sk)

        return res

    def decryptJSON(self, key):
        res = self._symmetricDecrypt(key)
        if res.ContentType != JSON_MIME:
            raise CryptoException("Invalid data type, not '%s'" % JSON_MIME)
        js = JSONloads(res.Data)
        return js
