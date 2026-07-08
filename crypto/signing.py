from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP

def sign_mess(data, private_key):
    h = SHA1.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_mess(data, signature, public_key):
    h = SHA1.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError):
        return False

def rsa_encrypt(data, public_key):
    return PKCS1_OAEP.new(public_key).encrypt(data)

def rsa_decrypt(ciphertext, private_key):
    return PKCS1_OAEP.new(private_key).decrypt(ciphertext)