import hashlib
import json
from base64 import b64decode
from Crypto.Cipher import AES
import requests

def get_crypto_initializers():
    routes_list = requests.get("https://maps.amtrak.com/rttl/js/RoutesList.json").json()
    master_zoom = sum(route.get("ZoomLevel", 0) for route in routes_list)

    crypto_data = requests.get("https://maps.amtrak.com/rttl/js/RoutesList.v.json").json()
    return {
        "public_key": crypto_data["arr"][master_zoom],
        "salt": bytes.fromhex(crypto_data["s"][len(crypto_data["s"][0])]),
        "iv": bytes.fromhex(crypto_data["v"][len(crypto_data["v"][0])])
    }

def decrypt(ciphertext_b64, password, salt, iv):
    ciphertext = b64decode(ciphertext_b64)
    key = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 1000, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted[:-decrypted[-1]].decode()

def parse_encrypted_data(encrypted_data):
    crypto = get_crypto_initializers()
    MASTER_SEGMENT = 88

    ciphertext = encrypted_data[:-MASTER_SEGMENT]
    private_key_cipher = encrypted_data[-MASTER_SEGMENT:]

    private_key = decrypt(private_key_cipher, crypto["public_key"], crypto["salt"], crypto["iv"]).split("|")[0]
    decrypted = decrypt(ciphertext, private_key, crypto["salt"], crypto["iv"])
    return json.loads(decrypted)
