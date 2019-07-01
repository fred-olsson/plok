#!/usr/bin/env python3
import os
import sys
import base64
from getpass import getpass 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

#TODO:
#b64urlsafe
#add install and set up folders.
#TMPsalt use: os.random(16)

tmp_pw = {
    'spicey': b'\x8ds U\xc3d\xa7\xce\xad\x7f\x01\rX\xde\xaf\xb6', 
    'skeleton': 'Dm1We0qIUPgaesn_Gs2nAmGKKcHMTegvMm_tO8ou0p0=',
    'facebook': 'gAAAAABcvRYJC8HYNRGm6M4Uh_nXg-cGUc5N_IwDuUCos4a1AwRV2OYHVC1XAMybyyFU7FbQlFt9tnU_zxTNWZXFL2-EZS2eOQ==',
    'youtube': 'qwerty'
}

def main(loc_id):
    pass_hash = gen_hash(get_pass()).decode()
    if (pass_hash == tmp_pw['skeleton']):
        print(tmp_pw[loc_id])
    else:
        exit('Unauthorized!')
    test1 = encrypt_pass('asdf', tmp_pw['skeleton'])
    print(test1)
    test1 = test1.decode()
    test2 = decrypt_pass(test1, 'Dm1We0qIUPgaesn/Gs2nAmGKKcHMTegvMm/tO8ou0p3=')
    print(test2)
    tmp_setup()
    #unmatching keys still decrypt? Only if changed at the end
    try:
        print(decrypt_pass(tmp_pw[sys.argv[1]], pass_hash))
    except InvalidToken:
        print('Unauthorized!')
    except:
        print(sys.exc_info())
 
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
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=tmp_pw['spicey'],
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(user_pass))

#encrypt/decrypt passwords using Fernet. Returns a b64 byte-object
def encrypt_pass(unenc_pass, key):
    key = key.encode()
    unenc_pass = unenc_pass.encode()
    fer = Fernet(key)
    return fer.encrypt(unenc_pass)
    
def decrypt_pass(enc_pass, key):
    key = key.encode()
    enc_pass = enc_pass.encode()
    fer = Fernet(key)
    return fer.decrypt(enc_pass)

#generate salt and setup files.
def tmp_setup():
    fname = base64.urlsafe_b64encode(os.urandom(16)).decode()
    fname = fname + '.pdb'
    f = open(fname, 'w+')
    f.close()


if __name__ == '__main__':
    main(sys.argv[1])