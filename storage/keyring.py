from cryptography.hazmat.primitives import serialization

class PublicKeyRing:
    def __init__(self, public_key):
        self.public_key = serialization.load_pem_public_key()

    def load(self):
