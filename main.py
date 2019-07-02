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
    test1 = encrypt_file('asdf', tmp_pw['skeleton'])
    print(test1)
    test1 = test1.decode()
    test2 = decrypt_file(test1, 'Dm1We0qIUPgaesn/Gs2nAmGKKcHMTegvMm/tO8ou0p3=')
    print(test2)
    get_salt()
    #unmatching keys still decrypt? Only if changed at the end
    try:
        print(decrypt_file(tmp_pw[sys.argv[1]], pass_hash))
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
def encrypt_file(unenc_file, key):
    key = key.encode()
    unenc_file = unenc_file.encode()
    fer = Fernet(key)
    return fer.encrypt(unenc_file)
    
def decrypt_file(enc_file, key):
    key = key.encode()
    enc_file = enc_file.encode()
    fer = Fernet(key)
    return fer.decrypt(enc_file)

#generate salt and setup dbfile.
def create_db():
    fname = os.urandom(16).hex()
    f = open(fname + '.dbdecr', 'w+')
    f.close()

def get_salt():   
    for f in os.listdir(os.getcwd()):
        if f.endswith('.dbdecr') or f.endswith('.dbencr'):
            print(f.split('.')[0])

if __name__ == '__main__':
    main(sys.argv[1])