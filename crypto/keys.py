from Crypto.PublicKey import RSA

def generate_rsa_keypair(key_size):
    if not(key_size == 1024 or key_size == 2048):
        raise ValueError('Key size must be 1024 or 2048')

    return RSA.generate(key_size) # podrazumevano koristi e = 65537

def calc_key_id(key):
    return format(key.n & 0xFFFFFFFFFFFFFFFF, "016x")

def public_key_to_pem(public_key):
    return public_key.export_key(format = 'PEM').decode('ascii')

def pem_to_public_key(pem_str):
    return RSA.import_key(pem_str.encode('ascii'))

def export_public_pem(public_key, path):
    data = public_key.export_key(format = 'PEM')
    with open(path, 'wb') as f:
        f.write(data)

def export_keypair_pem(private_key, path, passphrase):
    data = private_key.export_key(format = 'PEM', passphrase = passphrase, pkcs=8, protection='PBKDF2WithHMAC-SHA1AndAES128-CBC')
    with open(path, "wb") as f:
        f.write(data)

def import_pem(path, passphrase=None):
    with open(path, "rb") as f:
        data = f.read()
    if b"PUBLIC KEY" in data:
        return "public", RSA.import_key(data)
    else:
        return "private", RSA.import_key(data, passphrase=passphrase)