import base64, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def test_aesgcm_encrypt_decrypt():
    key = os.urandom(32)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    data = b'hello world'
    ct = aes.encrypt(nonce, data, None)
    pt = aes.decrypt(nonce, ct, None)
    assert pt == data
