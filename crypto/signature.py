from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15

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