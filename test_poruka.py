from crypto.keys import generate_rsa_keypair, calc_key_id
from crypto import message, signing, symmetric

# Ana (posiljalac) i Bora (primalac)
ana = generate_rsa_keypair(2048)
bora = generate_rsa_keypair(2048)
ana_kid = calc_key_id(ana)
bora_kid = calc_key_id(bora)

poruka = "Zdravo Bora, vidimo se u 5! čćžđš".encode("utf-8")

# --- SLANJE: svi servisi ukljuceni ---
fajl = message.build_message(
    data=poruka,
    filename="poruka.txt",
    sign_priv=ana, sender_key_id=ana_kid,          # potpis Aninim privatnim
    enc_pub=bora.publickey(), recipient_key_id=bora_kid, algo=symmetric.ALGO_AES128,
    compress=True,
    radix64=True,
)
print("Velicina .msg fajla:", len(fajl), "bajtova")
print("Pocinje sa radix-64 omotacem:", fajl[:27].decode("ascii"))

# --- PRIJEM ---
# 1) ko treba da desifruje?
print("Potreban privatni kljuc (recipient_key_id):", message.read_recipient_key_id(fajl),
      "== Borin:", message.read_recipient_key_id(fajl) == bora_kid)

# 2) rastavi (Bora koristi svoj privatni)
r = message.parse_message(fajl, private_key=bora)
print("Flegovi -> potpisan:", r["signed"], "| sifrovan:", r["encrypted"], "| kompresovan:", r["compressed"])

# 3) verifikacija (pozivalac nadje Anin javni po sender_key_id)
validan = signing.verify_mess(r["data"], r["signature"], ana.publickey())
print("Autor (sender_key_id):", r["sender_key_id"], "== Anin:", r["sender_key_id"] == ana_kid)
print("Potpis validan:", validan)
print("Poruka:", r["data"].decode("utf-8"))

# --- slucaj sa izmenom: promeni jedan bajt sadrzaja pre verifikacije ---
izmenjena = bytearray(r["data"]); izmenjena[0] ^= 0x01
print("Verifikacija izmenjene poruke:", signing.verify_mess(bytes(izmenjena), r["signature"], ana.publickey()))

print("\nOcekivano: recipient == True, potpis validan True, izmenjena False")
