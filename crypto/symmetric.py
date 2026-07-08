from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes

ALGO_AES128 = 1
ALGO_3DES = 2

ALGORITHMS = {
    ALGO_AES128: {"name": "AES-128", "key_len": 16, "iv_len": 16},
    ALGO_3DES: {"name": "3DES", "key_len": 24, "iv_len": 8},
}

def algo_name(algo_id):
    return ALGORITHMS[algo_id]["name"]

def _new_cipher(algo_id, key, iv):
    if algo_id == ALGO_AES128:
        return AES.new(key, AES.MODE_CFB, iv)
    elif algo_id == ALGO_3DES:
        return DES3.new(key, DES3.MODE_CFB, iv)
    raise ValueError("Nepoznat algoritam")

def generate_session_key(algo_id):
    return get_random_bytes(int(ALGORITHMS[algo_id]["key_len"]))

def encrypt(algo_id, key, plaintext):
    iv = get_random_bytes(int(ALGORITHMS[algo_id]["iv_len"]))
    cipher = _new_cipher(algo_id, key, iv)
    ciphertext = cipher.encrypt(plaintext)
    return iv, ciphertext

def decrypt(algo_id, key, iv, ciphertext):
    cipher = _new_cipher(algo_id, key, iv)
    return cipher.decrypt(ciphertext)
