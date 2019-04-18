#!/usr/bin/env python3
import os
import sys
import base64
from getpass import getpass 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

tmp_pw = {
    'skeleton': 'Dm1We0qIUPgaesn/Gs2nAmGKKcHMTegvMm/tO8ou0p0=',
    'facebook': 'asdf',
    'youtube': 'qwerty'
}

def main(loc_id):
    pass_hash = gen_hash(get_pass()).decode()
    if (pass_hash == tmp_pw['skeleton']):
        print(tmp_pw[loc_id])
    else:
        exit('Unauthorized!')
 
#get user input and return it as a byte-object
def get_pass():
    print('Password:')
    try:
        user_data = getpass('> ')
    except:
        print(sys.exc_info())
    return user_data.encode()

#generate hash from userinput with kdf. returns a b64 byte-object
def gen_hash(user_pass):
    #TMPsalt use: os.random(16)
    salt = b'\x8ds U\xc3d\xa7\xce\xad\x7f\x01\rX\xde\xaf\xb6'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.b64encode(kdf.derive(user_pass))

if __name__ == '__main__':
    main(sys.argv[1])
