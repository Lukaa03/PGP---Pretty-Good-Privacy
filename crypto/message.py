import zlib
import base64
import time

from crypto import signing, symmetric

FLAG_SIGNED     = 0b0001
FLAG_ENCRYPTED  = 0b0010
FLAG_COMPRESSED = 0b0100

HEADER = b"-----BEGIN PGP MESSAGE-----\n"
FOOTER = b"\n-----END PGP MESSAGE-----"



def _put(block):
    size_in_bytes = len(block).to_bytes(4, byteorder='big')
    return size_in_bytes + block

def _get(txt, offset):
    length = int.from_bytes(txt[offset:offset+4], 'big')
    start = offset + 4
    content = txt[start:start+length]
    return content, start + length


def remove_radix(raw):
    if raw.lstrip().startswith(b"-----BEGIN PGP MESSAGE-----"):
        inner = raw.split(b"-----BEGIN PGP MESSAGE-----", 1)[1]
        inner = inner.split(b"-----END PGP MESSAGE-----", 1)[0]
        return base64.b64decode(inner.strip()), True
    return raw, False


# SLANJE
def build_message(data, filename="poruka.txt", sign_priv=None, sender_key_id=None,
                  enc_pub=None, recipient_key_id=None, algo=None,
                  compress=False, radix64=False):
    flags = 0
    ts = time.strftime("%Y-%m-%d %H:%M:%S").encode("ascii")

    # potpis (opciono)
    if sign_priv is not None:
        flags |= FLAG_SIGNED
        signature = signing.sign_mess(data, sign_priv)
        sig_comp = _put(sender_key_id.encode("ascii")) + _put(ts) + _put(signature)
    else:
        sig_comp = b""

    # komponenta poruke
    msg_comp = _put(filename.encode("utf-8")) + _put(ts) + _put(data)

    inner = _put(sig_comp) + _put(msg_comp)

    # kompresija (posle potpisa, pre sifrovanja)
    if compress:
        flags |= FLAG_COMPRESSED
        inner = zlib.compress(inner)

    # sifrovanje
    if enc_pub is not None:
        flags |= FLAG_ENCRYPTED
        ks = symmetric.generate_session_key(algo)          # jednokratni kljuc sesije
        iv, ct = symmetric.encrypt(algo, ks, inner)        # simetricno sifruj sadrzaj
        enc_ks = signing.rsa_encrypt(ks, enc_pub)          # Ks sifruj javnim primaoca
        body = (_put(recipient_key_id.encode("ascii"))
                + bytes([algo])
                + _put(iv)
                + _put(enc_ks)
                + _put(ct))
    else:
        body = _put(inner)

    out = bytes([flags]) + body

    # radix-64
    if radix64:
        out = HEADER + base64.b64encode(out) + FOOTER
    return out


# PRIJEM
def read_recipient_key_id(raw):
    raw, _ = remove_radix(raw)
    flags = raw[0]
    if not (flags & FLAG_ENCRYPTED):
        return None
    recip, _ = _get(raw, 1)
    return recip.decode("ascii")


def parse_message(raw, private_key=None):
    raw, was_radix64 = remove_radix(raw)  # skini radix-64 ako ga ima
    flags = raw[0]                            # procitaj bajt flegova
    offset = 1

    result = {
        "radix64": was_radix64,
        "encrypted": bool(flags & FLAG_ENCRYPTED),
        "compressed": bool(flags & FLAG_COMPRESSED),
        "signed": bool(flags & FLAG_SIGNED),
    }

    # desifrovanje
    if flags & FLAG_ENCRYPTED:
        recip, offset = _get(raw, offset)
        algo = raw[offset]; offset += 1
        iv, offset = _get(raw, offset)
        enc_ks, offset = _get(raw, offset)
        ct, offset = _get(raw, offset)
        result["recipient_key_id"] = recip.decode("ascii")
        if private_key is None:
            raise ValueError("Poruka je sifrovana - potreban je privatni kljuc")
        ks = signing.rsa_decrypt(enc_ks, private_key)      # otkljucaj Ks svojim privatnim
        inner = symmetric.decrypt(algo, ks, iv, ct)        # desifruj sadrzaj sa Ks
    else:
        inner, offset = _get(raw, offset)

    # dekompresija
    if flags & FLAG_COMPRESSED:
        inner = zlib.decompress(inner)

    # razdvoj dve komponente
    sig_comp, p = _get(inner, 0)
    msg_comp, p = _get(inner, p)

    # iz sig_comp izvuci polja ako je potpisano
    if flags & FLAG_SIGNED:
        skid, q = _get(sig_comp, 0)
        sts, q = _get(sig_comp, q)
        signature, q = _get(sig_comp, q)
        result["sender_key_id"] = skid.decode("ascii")
        result["sig_timestamp"] = sts.decode("ascii")
        result["signature"] = signature

    # iz msg_comp izvuci polja
    fn, r = _get(msg_comp, 0)
    mts, r = _get(msg_comp, r)
    data, r = _get(msg_comp, r)
    result["filename"] = fn.decode("utf-8")
    result["timestamp"] = mts.decode("ascii")
    result["data"] = data
    return result
