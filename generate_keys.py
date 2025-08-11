# Generates strong AES-256 key (base64) and a Flask secret.
from base64 import b64encode
import os, secrets
key = os.urandom(32)  # 256-bit key
print('AES_KEY=' + b64encode(key).decode())
print('FLASK_SECRET=' + secrets.token_urlsafe(48))
