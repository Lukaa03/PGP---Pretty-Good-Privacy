# # # # # from crypto.keys import generate_rsa_keypair, public_key_to_pem, pem_to_public_key, calc_key_id
# # # # #
# # # # # priv = generate_rsa_keypair(2048)
# # # # # pem = public_key_to_pem(priv.public_key())
# # # # # print(pem)
# # # # # pub2 = pem_to_public_key(pem)
# # # # # print(calc_key_id(pub2))
# # # #
# # # # from storage.keyring import PublicKeyRing
# # # # from crypto.keys import generate_rsa_keypair
# # # #
# # # # ring = PublicKeyRing("public_ring.json")
# # # # priv = generate_rsa_keypair(2048)
# # # # unos = ring.add_public_key(priv.public_key(), "Luka", "luka@mail.com")
# # # # print("dodat:",unos["key_id"])
# # # #
# # # # ring2 = PublicKeyRing("public_ring.json")
# # # # print("Posle reload-a ima:", len(ring2.all()), "unosa")
# # # # print("Nadjen:", ring2.get_by_id(unos["key_id"]) is not None)
# # #
# # # from crypto.keys import generate_rsa_keypair, calc_key_id
# # #
# # # priv = generate_rsa_keypair(2048)
# # # kid = calc_key_id(priv.public_key())
# # # print("Key ID:", kid, "| duzina:", len(kid))
# # # assert len(kid) == 16                      # mora biti 16 hex cifara
# # #
# # # priv2 = generate_rsa_keypair(2048)         # drugi kljuc = drugi Key ID
# # # print("Drugi Key ID:", calc_key_id(priv2.public_key()))
# # #
# # # try:                                       # pogresna velicina mora da padne
# # #     generate_rsa_keypair(512)
# # #     print("GRESKA: nije bacio izuzetak")
# # # except ValueError as e:
# # #     print("Provera velicine radi:", e)
# #
# # from crypto.keys import generate_rsa_keypair, calc_key_id, public_key_to_pem, pem_to_public_key
# #
# # priv = generate_rsa_keypair(2048)
# # kid = calc_key_id(priv)
# # print("Key ID:", kid, "| duzina:",len(kid))
# #
# # pem = public_key_to_pem(priv.publickey())
# # print(pem[:40])
# # pub2 = pem_to_public_key(pem)
# # print("Ispit Key ID posle PEM tuda-nazad:", calc_key_id(pub2)==kid)
# #
# # try:
# #     generate_rsa_keypair(512)
# # except ValueError as e:
# #     print("Provara velicine radi:", e)
#
# from storage.keyring import PrivateKeyRing
#
# ring = PrivateKeyRing("private_ring.json")
# unos = ring.add_new_keypair("Luka","luka@mial.com", 2048, "mojalozinka")
# print("Dodat privatni kljuc:", unos["key_id"])
#
# print("Sifrovan:", "ENCRYPTED" in unos["enc_private"])
#
# k = ring.load_private_key(unos, "mojalozinka")
# print("Pristup tacnom lozinkom OK, Key ID:", format(k.n & 0xFFFFFFFFFFFFFFFF, "016x"))
#
# try:
#     ring.load_private_key(unos, "pogrena")
#     print("Greska: nije odbio pogresnu lozinku")
# except ValueError:
#     print("Pogresna lozinka ispravno odbijena")