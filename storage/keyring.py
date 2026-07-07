import os
import time
import json

from Crypto.PublicKey import RSA
from crypto.keys import calc_key_id, public_key_to_pem, pem_to_public_key, generate_rsa_keypair

# tudji javni kljucevi

class PublicKeyRing:
    def __init__(self, path):
        self.path = path
        self.entries = []
        self.load()

    def load(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                self.entries = json.load(f)
        else:
            self.entries = []

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.entries, f, ensure_ascii=False, indent=2)

    def get_by_id(self, key_id):
        for e in self.entries:
            if e["key_id"] == key_id:
                return e
        return None

    def add_public_key(self, public_key, name, email):
        entry = {
            "timestamp" : time.strftime("%Y-%m-%d %H:%M:%S"),
            "key_id" : calc_key_id(public_key),
            "name" : name,
            "email" : email,
            "public_pem" : public_key_to_pem(public_key)
        }
        if self.get_by_id(entry["key_id"]) is None:
            self.entries.append(entry)
            self.save()
        return entry

    def delete(self, key_id):
        self.entries = [e for e in self.entries if e["key_id"]!=key_id]
        self.save()

    def all(self):
        return self.entries


# tvoji parovi kljuceva, tj privatni

class PrivateKeyRing:
    def __init__(self, path):
        self.path = path
        self.entries = []
        self.load()

    def load(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                self.entries = json.load(f)
        else:
            self.entries = []

    def save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.entries, f, ensure_ascii=False, indent=2)

    def get_by_id(self, key_id):
        for e in self.entries:
            if e["key_id"] == key_id:
                return e
        return None

    def add_new_keypair(self, name, email, key_size, passphrase):
        key = generate_rsa_keypair(key_size)
        enc_private = key.export_key(format='PEM', passphrase=passphrase, pkcs=8)
        entry = {
            "timestamp" : time.strftime("%Y-%m-%d %H:%M:%S"),
            "key_id" : calc_key_id(key),
            "name": name,
            "email" : email,
            "key_size" : key_size,
            "public_pem" : public_key_to_pem(key.publickey()),
            "enc_private" : enc_private.decode("ascii")
        }
        self.entries.append(entry)
        self.save()
        return entry

    def load_private_key(self, entry, passphrase):
        return RSA.import_key(entry["enc_private"], passphrase=passphrase)

    def delete(self, key_id):
        self.entries = [e for e in self.entries if e["key_id"]!=key_id]
        self.save()

    def all(self):
        return self.entries