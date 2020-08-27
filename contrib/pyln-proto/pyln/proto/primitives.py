import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from binascii import hexlify


def varint_encode(i, w):
    """Encode an integer `i` into the writer `w`
    """
    if i < 0xFD:
        w.write(struct.pack("!B", i))
    elif i <= 0xFFFF:
        w.write(struct.pack("!BH", 0xFD, i))
    elif i <= 0xFFFFFFFF:
        w.write(struct.pack("!BL", 0xFE, i))
    else:
        w.write(struct.pack("!BQ", 0xFF, i))


def varint_decode(r):
    """Decode an integer from reader `r`
    """
    raw = r.read(1)
    if len(raw) != 1:
        return None

    i, = struct.unpack("!B", raw)
    if i < 0xFD:
        return i
    elif i == 0xFD:
        return struct.unpack("!H", r.read(2))[0]
    elif i == 0xFE:
        return struct.unpack("!L", r.read(4))[0]
    else:
        return struct.unpack("!Q", r.read(8))[0]


class ShortChannelId(object):
    def __init__(self, block, txnum, outnum):
        self.block = block
        self.txnum = txnum
        self.outnum = outnum

    @classmethod
    def from_bytes(cls, b):
        assert(len(b) == 8)
        i, = struct.unpack("!Q", b)
        return cls.from_int(i)

    @classmethod
    def from_int(cls, i):
        block = (i >> 40) & 0xFFFFFF
        txnum = (i >> 16) & 0xFFFFFF
        outnum = (i >> 0) & 0xFFFF
        return cls(block=block, txnum=txnum, outnum=outnum)

    @classmethod
    def from_str(self, s):
        block, txnum, outnum = s.split('x')
        return ShortChannelId(block=int(block), txnum=int(txnum),
                              outnum=int(outnum))

    def to_int(self):
        return self.block << 40 | self.txnum << 16 | self.outnum

    def to_bytes(self):
        return struct.pack("!Q", self.to_int())

    def __str__(self):
        return "{self.block}x{self.txnum}x{self.outnum}".format(self=self)

    def __eq__(self, other):
        return (
            self.block == other.block
            and self.txnum == other.txnum
            and self.outnum == other.outnum
        )


class Secret(object):
    def __init__(self, data: bytes):
        assert(len(data) == 32)
        self.data = data

    def to_bytes(self) -> bytes:
        return self.data

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and self.data == other.data

    def __str__(self):
        return "Secret[0x{}]".format(hexlify(self.data).decode('ASCII'))


class PrivateKey(object):
    def __init__(self, rawkey: bytes):
        assert(len(rawkey) == 32)
        self.rawkey = rawkey
        ikey = int.from_bytes(rawkey, byteorder='big')
        self.key = ec.derive_private_key(ikey, ec.SECP256K1(),
                                         default_backend())

    def serializeCompressed(self):
        return self.key.private_bytes(serialization.Encoding.Raw,
                                      serialization.PrivateFormat.Raw, None)

    def public_key(self):
        return PublicKey(self.key.public_key())


class PublicKey(object):
    def __init__(self, innerkey):
        # We accept either 33-bytes raw keys, or an EC PublicKey as returned
        # by cryptography.io
        if isinstance(innerkey, bytes):
            innerkey = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), innerkey
            )

        elif not isinstance(innerkey, ec.EllipticCurvePublicKey):
            raise ValueError(
                "Key must either be bytes or ec.EllipticCurvePublicKey"
            )
        self.key = innerkey

    def serializeCompressed(self):
        raw = self.key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint
        )
        return raw

    def to_bytes(self) -> bytes:
        return self.serializeCompressed()

    def __str__(self):
        return "PublicKey[0x{}]".format(
            hexlify(self.serializeCompressed()).decode('ASCII')
        )


def Keypair(object):
    def __init__(self, priv, pub):
        self.priv, self.pub = priv, pub
