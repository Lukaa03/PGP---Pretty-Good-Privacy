from crypto.keys import generate_rsa_keypair
from crypto.signature import sign_mess, verify_mess

# --- priprema ---
kljuc = generate_rsa_keypair(2048)          # ceo par (privatni + javni)
javni = kljuc.publickey()                   # samo javni deo, za verifikaciju

poruka = "Zdravo Bora, ovo je Ana.".encode("utf-8")   # data mora biti bajtovi

# --- 1. potpis pa verifikacija ispravne poruke -> True ---
potpis = sign_mess(poruka, kljuc)
print("1) validan potpis:", verify_mess(poruka, potpis, javni))          # ocekujemo True

# --- 2. izmenjena poruka -> False ---
izmenjena = "Zdravo Bora, ovo je Ana!".encode("utf-8")  # jedan znak drugaciji
print("2) izmenjena poruka:", verify_mess(izmenjena, potpis, javni))     # ocekujemo False

# --- 3. pogresan (tudji) javni kljuc -> False ---
drugi_kljuc = generate_rsa_keypair(2048)
print("3) pogresan kljuc:", verify_mess(poruka, potpis, drugi_kljuc.publickey()))  # ocekujemo False

# --- 4. ostecen potpis (promenjen jedan bajt) -> False ---
ostecen = bytearray(potpis)
ostecen[0] ^= 0x01                          # obrni jedan bit prvog bajta
print("4) ostecen potpis:", verify_mess(poruka, bytes(ostecen), javni))  # ocekujemo False

print("\nOcekivano: True, False, False, False")


# --- kolegin test za symmetric (sa origin/newBranch), za kasnije ---
# from crypto.symmetric import ALGO_AES128, ALGO_3DES, generate_session_key, encrypt, decrypt
#
# poruka = "tajna poruka čćžđš".encode("utf-8")
#
# for algo in (ALGO_AES128, ALGO_3DES):
#     kljuc = generate_session_key(algo)
#     iv, ct = encrypt(algo, kljuc, poruka)
#     nazad = decrypt(algo, kljuc, iv, ct)
#     print("Algoritam", algo, "OK:", nazad==poruka)
