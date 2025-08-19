import base64
import hashlib
email = input('Enter email: ')
password = input('Enter password: ')
hash_val = f'{password}{str(email).lower()}'
print(base64.b64encode(hashlib.sha256(hash_val.encode()).digest()))