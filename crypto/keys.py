from cryptography.hazmat.primitives.asymmetric import rsa

def generate_rsa_keypair(key_size):
    if key_size == 1024 or key_size == 2048:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    else:
        raise ValueError('Key size must be 1024 or 2048')
    return private_key

def calc_key_id(public_key):
    n = public_key.public_numbers().n
    broj = n & 0xFFFFFFFFFFFFFFFF
    key_id = format(broj, "016x")
    return key_id