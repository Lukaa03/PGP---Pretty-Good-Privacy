"""
DEMO: ceo PGP tok Ana -> Bora, koristeci postojece funkcije iz projekta.
Nije finalna aplikacija (fali kompresija, radix-64 i pravi format fajla),
nego prikaz kako se svi delovi uklapaju. Pokreni: python demo_tok.py
"""
import os
from storage.keyring import PrivateKeyRing, PublicKeyRing
from crypto.keys import pem_to_public_key
from crypto.signing import sign_mess, verify_mess, rsa_encrypt, rsa_decrypt
from crypto import symmetric

# ocisti stare json fajlove da demo bude ponovljiv
for f in ["ana_private.json", "ana_public.json", "bora_private.json", "bora_public.json"]:
    if os.path.exists(f):
        os.remove(f)

# ============================================================
# FAZA 1: Ana i Bora prave svoje parove kljuceva
# ============================================================
ana_priv_ring = PrivateKeyRing("ana_private.json")   # Anini parovi
ana_pub_ring  = PublicKeyRing("ana_public.json")     # javni kljucevi koje Ana poznaje
bora_priv_ring = PrivateKeyRing("bora_private.json") # Borini parovi
bora_pub_ring  = PublicKeyRing("bora_public.json")   # javni kljucevi koje Bora poznaje

# Svako pri generisanju bira lozinku kojom se stiti njegov privatni kljuc
ana_entry  = ana_priv_ring.add_new_keypair("Ana",  "ana@mail.com",  2048, "ana-lozinka")
bora_entry = bora_priv_ring.add_new_keypair("Bora", "bora@mail.com", 2048, "bora-lozinka")
print("Ana Key ID :", ana_entry["key_id"])
print("Bora Key ID:", bora_entry["key_id"])

# ============================================================
# FAZA 2: razmena JAVNIH kljuceva (u pravoj app preko .pem fajlova)
# ============================================================
# Bora dobija Anin javni kljuc i stavlja ga u svoj prsten javnih kljuceva
ana_pub = pem_to_public_key(ana_entry["public_pem"])
bora_pub_ring.add_public_key(ana_pub, "Ana", "ana@mail.com")

# Ana dobija Borin javni kljuc i stavlja ga u svoj prsten
bora_pub = pem_to_public_key(bora_entry["public_pem"])
ana_pub_ring.add_public_key(bora_pub, "Bora", "bora@mail.com")

# ============================================================
# FAZA 3: ANA SALJE poruku Bori (tajnost + autenticnost)
# ============================================================
poruka = "Zdravo Bora, vidimo se u 5!".encode("utf-8")

# (1) POTPIS: Ana treba svoj PRIVATNI kljuc -> mora da unese lozinku
ana_private = ana_priv_ring.load_private_key(ana_entry, "ana-lozinka")
potpis = sign_mess(poruka, ana_private)

# (2) spoji potpis + poruku (privremen prost format: 2 bajta = duzina potpisa)
#     [ovde bi u pravoj app dosla KOMPRESIJA]
paket = len(potpis).to_bytes(2, "big") + potpis + poruka

# (3) SIMETRICNO SIFROVANJE: napravi jednokratni kljuc sesije i sifruj paket
algo = symmetric.ALGO_AES128
ks = symmetric.generate_session_key(algo)
iv, sifrovan_paket = symmetric.encrypt(algo, ks, paket)

# (4) SIFRUJ KLJUC SESIJE Borinim JAVNIM kljucem (uzmi ga iz prstena po Key ID-u)
bora_pub_iz_prstena = pem_to_public_key(
    ana_pub_ring.get_by_id(bora_entry["key_id"])["public_pem"]
)
sifrovan_ks = rsa_encrypt(ks, bora_pub_iz_prstena)

#     [ovde bi doslo RADIX-64 i upis u poruka.msg]
# Ovo su podaci koji putuju do Bore:
posiljka = {
    "algo": algo,
    "sender_key_id": ana_entry["key_id"],   # da Bora zna cijim javnim da verifikuje
    "enc_session_key": sifrovan_ks,
    "iv": iv,
    "ciphertext": sifrovan_paket,
}
print("\nAna poslala posiljku (sifrovano). Duzina ciphertext-a:", len(sifrovan_paket))

# ============================================================
# FAZA 4: BORA PRIMA poruku (obrnutim redom)
# ============================================================
#     [ovde bi Bora prvo skinuo RADIX-64]

# (1) OTKLJUCAJ KLJUC SESIJE: Bora treba svoj PRIVATNI kljuc -> unosi lozinku
bora_private = bora_priv_ring.load_private_key(bora_entry, "bora-lozinka")
ks_primljen = rsa_decrypt(posiljka["enc_session_key"], bora_private)

# (2) DESIFRUJ paket kljucem sesije
paket_primljen = symmetric.decrypt(
    posiljka["algo"], ks_primljen, posiljka["iv"], posiljka["ciphertext"]
)
#     [ovde bi dosla DEKOMPRESIJA]

# (3) razdvoji potpis i poruku
duz = int.from_bytes(paket_primljen[:2], "big")
potpis_primljen = paket_primljen[2:2+duz]
poruka_primljena = paket_primljen[2+duz:]

# (4) VERIFIKACIJA: nadji Anin javni kljuc u prstenu (po sender_key_id) i proveri potpis
ana_pub_iz_prstena = pem_to_public_key(
    bora_pub_ring.get_by_id(posiljka["sender_key_id"])["public_pem"]
)
validan = verify_mess(poruka_primljena, potpis_primljen, ana_pub_iz_prstena)

print("Potpis validan:", validan)
print("Desifrovana poruka:", poruka_primljena.decode("utf-8"))
