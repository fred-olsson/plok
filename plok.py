#!/usr/bin/env python3
import os
import sys
import json
import base64
import random
import string
from getpass import getpass 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

#TODO:
#switching to file encryption and json
#put, delete pw from db. 

def main(loc_id):
    #pass_hash = gen_hash(get_pass())
    #create_db()
    for i in range(10):
        gen_pass(20, 'facebook%d' % i )

    # try:
    #     print(decrypt_file(pass_hash))
    # except InvalidToken:
    #     print('Unauthorized!')
    # except:
    #     print(sys.exc_info())
 
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
        salt=bytes.fromhex(get_spice()),
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(user_pass))

#encrypt/decrypt files using Fernet.
# def encrypt_file(unenc_file, key):
#     key = key.encode()
#     unenc_file = unenc_file.encode()
#     fer = Fernet(key)
#     return fer.encrypt(unenc_file)

# def decrypt_file(enc_file, key):
#     key = key.encode()
#     enc_file = enc_file.encode()
#     fer = Fernet(key)
#     return fer.decrypt(enc_file)

#not tested
def encrypt_file(key):
    fname = get_spice + '.json'
    with open(fname, mode='rb') as f:
        data = json.loads(f.read())
        f.close()
    with open(fname, mode='w') as f:
        fer = Fernet(key)
        encr_file = fer.encrypt(data)
        f.write(encr_file)
        f.close()

def decrypt_file(key):
    fname = get_spice + '.json'
    with open(fname, mode='rb') as f:
        data = f.read()
        f.close()
    with open(fname, mode='w') as f:
        fer = Fernet(key)
        decr_file = json.loads(fer.decrypt(data))
        f.write(decr_file)
        f.close()

#generate password and put it in db
def gen_pass(pw_len, service):
    letters_digits = string.ascii_letters + string.digits
    pw_data = {service: ''.join(random.choice(letters_digits) for i in range(pw_len))}
    file_size = os.path.getsize(get_spice() + '.json')
    if file_size > 0:
        with open(get_spice() + '.json', mode='r') as f:
            f_json = json.load(f)
            f.close()
        with open(get_spice() + '.json', mode='w') as f:
            f_json.update(pw_data)
            json.dump(f_json, f)
            f.close()
    else:
        with open(get_spice() + '.json', mode='w') as f:
            json.dump(pw_data, f)
            f.close()

#generate salt and setup dbfile.
def create_db():
    fname = os.urandom(16).hex()
    with open(fname + '.json', mode='w+', encoding='utf-8') as f:
        f.close()

def get_spice():   
    for file in os.listdir(os.getcwd()):
        if file.endswith('.json'):
            return file.split('.')[0]

if __name__ == '__main__':
    main(sys.argv[1])